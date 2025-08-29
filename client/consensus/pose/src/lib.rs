//! PoSE consensus primitives: AppCrypto key types and engine id.

#![forbid(unsafe_code)]

use parity_scale_codec::{Decode, Encode};
use sc_network::config::NonDefaultSetConfig;
use sc_network::types::ProtocolName;
use sp_core::{crypto::KeyTypeId, H256};
use sp_runtime::{ConsensusEngineId, RuntimeDebug};

/// Consensus engine identifier for PoSE.
/// Chosen 4-byte ID: "POSE".
pub const POSE_ENGINE_ID: ConsensusEngineId = *b"POSE";

/// PoSE VRF application crypto.
pub mod pose_vrf {
    use super::*;
    use sp_application_crypto::app_crypto;
    use sp_core::sr25519;

    /// Key type ID for PoSE VRF keys.
    pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"pvrf");

    // Bind the sr25519 crypto to the given key type for runtime/app usage.
    app_crypto!(sr25519, KEY_TYPE);

    // Aliases commonly used by Substrate code.
    pub type AuthorityId = Public;
    pub type AuthoritySignature = Signature;
}

/// PoSE BLS application crypto.
/// Note: sp_application_crypto currently supports ed25519/sr25519/ecdsa pairs for keystore
/// integration. This binds an ed25519 key type to `pbls` so keys can be managed via keystore
/// under the PoSE-BLS key type, while BLS-specific handling can be layered separately.
pub mod pose_bls {
    use super::*;
    use sp_application_crypto::app_crypto;
    use sp_core::ed25519;

    /// Key type ID for PoSE BLS-like keys.
    pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"pbls");

    // Bind ed25519 as a placeholder for keystore management under the BLS key type.
    app_crypto!(ed25519, KEY_TYPE);

    pub type AuthorityId = Public;
    pub type AuthoritySignature = Signature;
}

// Keep explicit deps referenced to avoid accidental removal; real usage comes later.
#[allow(unused_imports)]
use bls12_381 as _;
#[allow(unused_imports)]
use schnorrkel as _;

/// Alias for a generic 32-byte account identifier used across Substrate.
pub type AccountId = sp_core::crypto::AccountId32;

/// Pre-runtime digest attached to PoSE-authored blocks.
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub struct PreRuntimeDigest {
    pub epoch: u64,
    pub seed: H256,
    pub leader: AccountId,
}

/// Kind of vote in PoSE finality gadget.
#[derive(Copy, Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

/// A PoSE vote digest embedded in block headers during finality rounds.
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub struct VoteDigest {
    pub kind: VoteKind,
    pub round: u64,
    pub epoch: u64,
    pub agg_sig: [u8; 96],
    pub bitmap: Vec<u8>,
}

/// A PoSE justification which proves finality for a block.
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub struct Justification {
    pub round: u64,
    pub epoch: u64,
    pub agg_sig: [u8; 96],
    pub bitmap: Vec<u8>,
}

//
// Networking: protocol, topics, and message validation
//

/// Returns the PoSE notifications protocol name.
pub fn protocol_name() -> ProtocolName {
    ProtocolName::from("/pose/1")
}

/// Build a default notification peers set config for PoSE.
/// Allows non-reserved peers; sets a conservative max notification size.
pub fn peers_set_config() -> NonDefaultSetConfig {
    const MAX_SIZE: u64 = 8 * 1024; // 8 KiB per notification
    let mut cfg = NonDefaultSetConfig::new(protocol_name(), MAX_SIZE);
    cfg.allow_non_reserved(64, 64);
    cfg
}

/// Gossip topics within PoSE.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TopicKind {
    Proposal,
    Prevote,
    Precommit,
    AggVote,
    Justification,
}

/// String form of the topic, derived from the protocol name.
pub fn topic_name(kind: TopicKind) -> String {
    match kind {
        TopicKind::Proposal => format!("{}/proposal", &*protocol_name()),
        TopicKind::Prevote => format!("{}/prevote", &*protocol_name()),
        TopicKind::Precommit => format!("{}/precommit", &*protocol_name()),
        TopicKind::AggVote => format!("{}/aggvote", &*protocol_name()),
        TopicKind::Justification => format!("{}/justification", &*protocol_name()),
    }
}

/// Validation errors for incoming PoSE gossip messages.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ValidationError {
    #[error("message too large: {0} > {1}")]
    MessageTooLarge(usize, usize),
    #[error("SCALE decode failed")]
    Decode,
    #[error("unexpected epoch: got {got}, expected {expected}")]
    WrongEpoch { got: u64, expected: u64 },
    #[error("unexpected round: got {got}, expected {expected}")]
    WrongRound { got: u64, expected: u64 },
    #[error("unexpected group: got {got:?}, expected {expected:?}")]
    WrongGroup { got: Option<u64>, expected: Option<u64> },
    #[error("unexpected vote kind")]
    WrongVoteKind,
}

/// Context for validating messages.
#[derive(Clone, Debug)]
pub struct ValidationContext {
    pub epoch: u64,
    pub round: u64,
    pub group: Option<u64>,
}

/// Trait exposing epoch/round fields for validation.
pub trait HasEpochRound {
    fn epoch(&self) -> u64;
    fn round(&self) -> u64;
}

impl HasEpochRound for VoteDigest {
    fn epoch(&self) -> u64 { self.epoch }
    fn round(&self) -> u64 { self.round }
}

impl HasEpochRound for Justification {
    fn epoch(&self) -> u64 { self.epoch }
    fn round(&self) -> u64 { self.round }
}

/// Optional group extraction for validation.
pub trait MaybeHasGroup {
    fn group(&self) -> Option<u64> { None }
}

impl MaybeHasGroup for VoteDigest {}
impl MaybeHasGroup for Justification {}

/// Validate a SCALE-encoded message with epoch/round and optional group checks.
pub fn validate_message<T>(
    bytes: &[u8],
    max_size: usize,
    ctx: &ValidationContext,
) -> Result<T, ValidationError>
where
    T: Decode + HasEpochRound + MaybeHasGroup,
{
    if bytes.len() > max_size {
        return Err(ValidationError::MessageTooLarge(bytes.len(), max_size))
    }

    let msg = T::decode(&mut &*bytes).map_err(|_| ValidationError::Decode)?;

    if msg.epoch() != ctx.epoch {
        return Err(ValidationError::WrongEpoch { got: msg.epoch(), expected: ctx.epoch })
    }
    if msg.round() != ctx.round {
        return Err(ValidationError::WrongRound { got: msg.round(), expected: ctx.round })
    }

    let got_group = msg.group();
    if got_group != ctx.group {
        return Err(ValidationError::WrongGroup { got: got_group, expected: ctx.group })
    }

    Ok(msg)
}

/// Validate a vote digest for a specific vote kind.
pub fn validate_vote(
    bytes: &[u8],
    kind: VoteKind,
    max_size: usize,
    ctx: &ValidationContext,
) -> Result<VoteDigest, ValidationError> {
    let v: VoteDigest = validate_message(bytes, max_size, ctx)?;
    if v.kind != kind { return Err(ValidationError::WrongVoteKind) }
    Ok(v)
}

/// Suggested size limits per topic (in bytes).
pub mod limits {
    pub const PROPOSAL_MAX: usize = 128 * 1024; // depends on block header/body
    pub const VOTE_MAX: usize = 4 * 1024; // includes agg sig + bitmap
    pub const JUSTIFICATION_MAX: usize = 8 * 1024; // aggregated justification
}

//
// Proposer: ordering and helpers
//
use sp_runtime::traits::{BlakeTwo256, Hash as HashT};

/// Compute ordering key for a transaction hash given the epoch seed.
pub fn ordering_key(tx_hash: sp_core::H256, epoch_seed: H256) -> sp_core::H256 {
    let xored = {
        let mut a = *tx_hash.as_fixed_bytes();
        let b = epoch_seed.as_fixed_bytes();
        for i in 0..32 { a[i] ^= b[i]; }
        sp_core::H256::from(a)
    };
    // Rehash for better distribution
    BlakeTwo256::hash(xored.as_bytes())
}

/// Order extrinsics by XOR distance to the epoch seed.
pub fn order_extrinsics<E>(epoch_seed: H256, mut items: Vec<(sp_core::H256, E)>) -> Vec<E> {
    items.sort_by_key(|(h, _)| ordering_key(*h, epoch_seed));
    items.into_iter().map(|(_, e)| e).collect()
}

/// Block proposer helper that can sort pool transactions deterministically per epoch.
pub struct PoSEProposer;

impl PoSEProposer {
    /// Given transaction hashes and extrinsics, return ordered extrinsics.
    pub fn propose_body<E>(epoch_seed: H256, pool: Vec<(sp_core::H256, E)>) -> Vec<E> {
        order_extrinsics(epoch_seed, pool)
    }
}

//
// Import queue: verifier that checks PoSE digests and basic thresholds (no-op crypto)
//
use sc_consensus::import_queue::{BasicQueue, DefaultImportQueue, Verifier as ImportVerifier};
use sc_consensus::{block_import::BoxBlockImport, import_queue::BoxJustificationImport};
use sp_runtime::traits::Block as BlockT;

/// Threshold t=floor(2n/3)+1 for a given committee size.
pub fn quorum_threshold(n: usize) -> usize { (2 * n) / 3 + 1 }

/// Placeholder BLS aggregate signature verification.
fn verify_bls_aggregate(_msg: &[u8], _agg_sig: &[u8;96], _bitmap: &[u8]) -> bool { true }

/// A minimal PoSE verifier that decodes PoSE digests and performs size/quorum checks.
pub struct PoSEVerifier {
    pub expected_epoch: u64,
    pub expected_round: u64,
    pub committee_size: usize,
}

#[async_trait::async_trait]
impl<B: BlockT> ImportVerifier<B> for PoSEVerifier {
    async fn verify(&mut self, mut block: sc_consensus::block_import::BlockImportParams<B>)
        -> Result<sc_consensus::block_import::BlockImportParams<B>, String>
    {
        let header = block.header.clone();
        for log in header.digest().logs() {
            match log {
                sp_runtime::DigestItem::PreRuntime(id, data) if id == &POSE_ENGINE_ID => {
                    let pre = PreRuntimeDigest::decode(&mut &data[..])
                        .map_err(|_| "bad PoSE pre-runtime digest".to_string())?;
                    if pre.epoch != self.expected_epoch { return Err("wrong epoch".into()) }
                }
                sp_runtime::DigestItem::Consensus(id, data) if id == &POSE_ENGINE_ID => {
                    // Try vote or justification
                    if let Ok(v) = VoteDigest::decode(&mut &data[..]) {
                        if v.epoch != self.expected_epoch { return Err("wrong epoch".into()) }
                        if v.round != self.expected_round { return Err("wrong round".into()) }
                        // Size check
                        if data.len() > limits::VOTE_MAX { return Err("vote too large".into()) }
                    } else if let Ok(j) = Justification::decode(&mut &data[..]) {
                        if j.epoch != self.expected_epoch { return Err("wrong epoch".into()) }
                        if j.round != self.expected_round { return Err("wrong round".into()) }
                        if data.len() > limits::JUSTIFICATION_MAX { return Err("justification too large".into()) }
                        // Quorum check placeholder
                        if self.committee_size > 0 {
                            let t = quorum_threshold(self.committee_size);
                            // bitmap popcount approximation
                            let votes = j.bitmap.iter().map(|b| b.count_ones() as usize).sum::<usize>();
                            if votes < t { return Err("insufficient quorum".into()) }
                        }
                        if !verify_bls_aggregate(&header.hash().as_ref()[..], &j.agg_sig, &j.bitmap) {
                            return Err("invalid aggregate signature".into())
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(sc_consensus::block_import::BlockImportParams::new(block.origin, header))
    }
}

/// Build a PoSE import queue with a basic verifier.
pub fn build_import_queue<B: BlockT>(
    expected_epoch: u64,
    expected_round: u64,
    committee_size: usize,
    block_import: BoxBlockImport<B>,
    justification_import: Option<BoxJustificationImport<B>>,
    spawner: &impl sp_core::traits::SpawnEssentialNamed,
    registry: Option<&prometheus_endpoint::Registry>,
) -> DefaultImportQueue<B> {
    let verifier = PoSEVerifier { expected_epoch, expected_round, committee_size };
    BasicQueue::new(verifier, block_import, justification_import, spawner, registry)
}

//
// Pacemaker: adaptive timeouts and view changes (skeleton)
//
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct PacemakerConfig {
    pub base_proposal: Duration,
    pub base_prevote: Duration,
    pub base_precommit: Duration,
    pub max_backoff: Duration,
}

impl Default for PacemakerConfig {
    fn default() -> Self {
        Self {
            base_proposal: Duration::from_millis(1000),
            base_prevote: Duration::from_millis(1000),
            base_precommit: Duration::from_millis(1000),
            max_backoff: Duration::from_millis(10_000),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pacemaker {
    cfg: PacemakerConfig,
    backoff: u32,
}

impl Pacemaker {
    pub fn new(cfg: PacemakerConfig) -> Self { Self { cfg, backoff: 0 } }

    pub fn on_timeout(&mut self) {
        self.backoff = (self.backoff + 1).min(8);
    }

    pub fn on_progress(&mut self) { self.backoff = 0; }

    pub fn proposal_timeout(&self) -> Duration {
        self.apply_backoff(self.cfg.base_proposal)
    }
    pub fn prevote_timeout(&self) -> Duration {
        self.apply_backoff(self.cfg.base_prevote)
    }
    pub fn precommit_timeout(&self) -> Duration {
        self.apply_backoff(self.cfg.base_precommit)
    }

    fn apply_backoff(&self, base: Duration) -> Duration {
        let factor = 1u32 << self.backoff;
        let ms = base.as_millis() as u64 * factor as u64;
        Duration::from_millis(ms.min(self.cfg.max_backoff.as_millis() as u64))
    }
}

//
// Leader election (single group)
//
use crate::pose_vrf::AuthorityId as VrfAuthorityId;

/// Deterministic leader election: smallest hash of (pubkey || seed) as placeholder.
pub fn elect_leader(authorities: &[VrfAuthorityId], seed: H256) -> Option<VrfAuthorityId> {
    authorities
        .iter()
        .min_by_key(|id| {
            let mut input = Vec::with_capacity(32 + 32);
            input.extend_from_slice(id.as_ref());
            input.extend_from_slice(seed.as_bytes());
            BlakeTwo256::hash(&input)
        })
        .cloned()
}

//
// Vote flow: simple aggregator with quorum threshold producing Justification
//
#[derive(Clone, Debug, Default)]
pub struct VoteAggregator {
    pub n: usize,
    pub bitmap: Vec<u8>,
    pub agg_sig: [u8; 96],
}

impl VoteAggregator {
    pub fn new(n: usize) -> Self { Self { n, bitmap: Vec::new(), agg_sig: [0u8; 96] } }

    /// Adds a vote from index `i` in the committee; updates bitmap.
    pub fn add_vote(&mut self, i: usize) {
        let byte = i / 8;
        let bit = i % 8;
        if self.bitmap.len() <= byte { self.bitmap.resize(byte + 1, 0); }
        self.bitmap[byte] |= 1 << bit;
    }

    pub fn has_quorum(&self) -> bool {
        let votes = self.bitmap.iter().map(|b| b.count_ones() as usize).sum::<usize>();
        votes >= quorum_threshold(self.n)
    }

    /// Finalize and build a justification for the given round/epoch.
    pub fn into_justification(self, round: u64, epoch: u64) -> Justification {
        Justification { round, epoch, agg_sig: self.agg_sig, bitmap: self.bitmap }
    }
}
