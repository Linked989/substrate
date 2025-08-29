//! PoSE consensus primitives: AppCrypto key types and engine id.

#![forbid(unsafe_code)]

use parity_scale_codec::{Decode, Encode};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use futures::{StreamExt as _, FutureExt as _};
use sc_network::{NetworkService, NetworkEventStream, NetworkNotification};
use libp2p::PeerId;
use sc_network::config::NonDefaultSetConfig;
use sc_network::types::ProtocolName;
use sp_core::{crypto::KeyTypeId, H256};
use sp_runtime::{ConsensusEngineId, RuntimeDebug};
use sp_consensus::{self, BlockOrigin};

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
#[derive(Copy, Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug, Hash)]
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
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    MessageTooLarge(usize, usize),
    Decode,
    WrongEpoch { got: u64, expected: u64 },
    WrongRound { got: u64, expected: u64 },
    WrongGroup { got: Option<u64>, expected: Option<u64> },
    WrongVoteKind,
}

impl core::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ValidationError::MessageTooLarge(got, max) => write!(f, "message too large: {} > {}", got, max),
            ValidationError::Decode => write!(f, "SCALE decode failed"),
            ValidationError::WrongEpoch { got, expected } => write!(f, "unexpected epoch: got {}, expected {}", got, expected),
            ValidationError::WrongRound { got, expected } => write!(f, "unexpected round: got {}, expected {}", got, expected),
            ValidationError::WrongGroup { got, expected } => write!(f, "unexpected group: got {:?}, expected {:?}", got, expected),
            ValidationError::WrongVoteKind => write!(f, "unexpected vote kind"),
        }
    }
}

impl std::error::Error for ValidationError {}

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
use sc_consensus::import_queue::{BoxBlockImport, BoxJustificationImport};
use sp_runtime::traits::Block as BlockT;
use sc_block_builder::{BlockBuilderProvider, RecordProof, BlockBuilderApi};
use sp_blockchain::HeaderBackend;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_inherents::InherentDataProvider;
use sp_runtime::traits::Header as _;
use sp_inherents::InherentData;
use sp_timestamp::InherentDataProvider as TimestampInherent;
use sp_runtime::DigestItem;
use sp_core::crypto::UncheckedFrom;

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
        use sp_runtime::traits::Header as _;
        let header = block.header.clone();
        for log in header.digest().logs() {
            match log {
                sp_runtime::DigestItem::PreRuntime(id, data) if *id == POSE_ENGINE_ID => {
                    let pre = PreRuntimeDigest::decode(&mut &data[..])
                        .map_err(|_| "bad PoSE pre-runtime digest".to_string())?;
                    if self.expected_epoch != u64::MAX && pre.epoch != self.expected_epoch {
                        return Err("wrong epoch".into())
                    }
                }
                sp_runtime::DigestItem::Consensus(id, data) if *id == POSE_ENGINE_ID => {
                    // Try vote or justification
                    if let Ok(v) = VoteDigest::decode(&mut &data[..]) {
                        if self.expected_epoch != u64::MAX && v.epoch != self.expected_epoch {
                            return Err("wrong epoch".into())
                        }
                        if self.expected_round != u64::MAX && v.round != self.expected_round {
                            return Err("wrong round".into())
                        }
                        // Size check
                        if data.len() > limits::VOTE_MAX { return Err("vote too large".into()) }
                    } else if let Ok(j) = Justification::decode(&mut &data[..]) {
                        if self.expected_epoch != u64::MAX && j.epoch != self.expected_epoch {
                            return Err("wrong epoch".into())
                        }
                        if self.expected_round != u64::MAX && j.round != self.expected_round {
                            return Err("wrong round".into())
                        }
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

pub mod justification;
pub use justification::PoseJustificationImport;

/// Construct a PoSE justification importer which finalizes blocks when PoSE justifications arrive.
pub fn justification_import<B, C, CB>(client: Arc<C>) -> sc_consensus::import_queue::BoxJustificationImport<B>
where
    B: BlockT + 'static,
    C: sc_client_api::backend::Finalizer<B, CB> + sp_blockchain::HeaderBackend<B> + Send + Sync + 'static,
    CB: sc_client_api::backend::Backend<B> + 'static,
{
    Box::new(PoseJustificationImport::<C, B, CB> { client, _m: core::marker::PhantomData })
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
#[derive(Clone, Debug)]
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

impl Default for VoteAggregator {
    fn default() -> Self { Self::new(0) }
}

//
// Gossip wire types and helpers
//
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub struct Proposal {
    pub epoch: u64,
    pub parent: H256,
    pub digest: Vec<u8>,
    pub block_parts: Vec<u8>,
    pub block_hash: H256,
}

#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub struct Vote {
    pub kind: VoteKind,
    pub round: u64,
    pub epoch: u64,
    pub block_hash: H256,
    pub sig_share: Vec<u8>,
    pub validator_idx: u32,
}

#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub struct AggVote {
    pub kind: VoteKind,
    pub round: u64,
    pub epoch: u64,
    pub block_hash: H256,
    pub agg_sig: [u8; 96],
    pub bitmap: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub enum WireMsg {
    Proposal(Proposal),
    Vote(Vote),
    AggVote(AggVote),
}

fn broadcast<B>(network: &NetworkService<B, H256>, peers: &Vec<PeerId>, protocol: &ProtocolName, msg: WireMsg)
where
    B: BlockT + 'static,
{
    let payload = msg.encode();
    for p in peers.iter().cloned() {
        network.write_notification(p, protocol.clone(), payload.clone());
    }
}

//
// PoSE authoring loop (prototype)
//
use log::{info, warn};

/// Parameters to start the PoSE authoring task.
pub struct StartParams<B: BlockT, BI, C, TP> {
    pub client: Arc<C>,
    pub pool: Arc<TP>,
    pub block_import: BI,
    pub authorities: Vec<sp_core::H256>,
    pub local_id: sp_core::H256,
    pub slot_duration: Duration,
    pub _phantom: core::marker::PhantomData<B>,
    pub network: Arc<NetworkService<B, H256>>,
}

/// Start a very simple slot-based authoring loop that produces blocks periodically.
/// This is a PoC: it builds inherents (timestamp) and imports the produced block.
pub async fn start<B, BI, C, TP, CB>(mut params: StartParams<B, BI, C, TP>)
where
    B: BlockT + 'static,
    BI: sc_consensus::block_import::BlockImport<B, Error = sp_consensus::Error> + Send + Sync + 'static,
    C: BlockBuilderProvider<CB, B, C> + HeaderBackend<B> + ProvideRuntimeApi<B> + Send + Sync + 'static,
    C::Api: ApiExt<B> + BlockBuilderApi<B>,
    CB: sc_client_api::backend::Backend<B> + Send + Sync + 'static,
    TP: sc_transaction_pool_api::TransactionPool<Block = B> + 'static,
    H256: From<<B as BlockT>::Hash>,
{
    let StartParams { client, mut block_import, slot_duration, local_id, authorities, network, .. } = params;
    let mut slot_counter: u64 = 0;
    let protocol = protocol_name();
    let mut events = network.event_stream("pose");
    let peers: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
    type VoteKey = (VoteKind, u64, u64, [u8; 32]);
    let votes: Arc<Mutex<HashMap<VoteKey, HashSet<u32>>>> = Arc::new(Mutex::new(HashMap::new()));
    let local_index: u32 = authorities
        .iter()
        .position(|h| *h == local_id)
        .map(|i| i as u32)
        .unwrap_or(0);

    loop {
        // Drain some network events without blocking.
        while let Some(ev) = events.next().now_or_never().flatten() {
            match ev {
                sc_network::event::Event::NotificationStreamOpened { remote, protocol: p, .. } => {
                    if p == protocol { peers.lock().unwrap().push(remote); }
                }
                sc_network::event::Event::NotificationsReceived { remote: _, messages } => {
                    for (p, bytes) in messages {
                        if p != protocol { continue }
                        if let Ok(msg) = WireMsg::decode(&mut &bytes[..]) {
                            match msg {
                                WireMsg::Proposal(prop) => {
                                    if prop.epoch <= slot_counter {
                                        let v = Vote {
                                            kind: VoteKind::Prevote,
                                            round: 0,
                                            epoch: prop.epoch,
                                            block_hash: prop.block_hash,
                                            sig_share: vec![],
                                            validator_idx: local_index,
                                        };
                                        broadcast(&*network, &*peers.lock().unwrap(), &protocol, WireMsg::Vote(v));
                                    }
                                }
                                WireMsg::Vote(v) => {
                                    let key = (v.kind, v.round, v.epoch, *v.block_hash.as_fixed_bytes());
                                    let mut guard = votes.lock().unwrap();
                                    let entry = guard.entry(key).or_insert_with(HashSet::new);
                                    entry.insert(v.validator_idx);
                                    let n = authorities.len().max(1);
                                    let t = quorum_threshold(n);
                                    if entry.len() >= t {
                                        let mut bitmap = Vec::new();
                                        for i in entry.iter() {
                                            let i = *i as usize;
                                            let byte = i / 8; let bit = i % 8;
                                            if bitmap.len() <= byte { bitmap.resize(byte + 1, 0); }
                                            bitmap[byte] |= 1 << bit;
                                        }
                                        let agg = AggVote {
                                            kind: v.kind,
                                            round: v.round,
                                            epoch: v.epoch,
                                            block_hash: v.block_hash,
                                            agg_sig: [0u8;96],
                                            bitmap,
                                        };
                                        broadcast(&*network, &*peers.lock().unwrap(), &protocol, WireMsg::AggVote(agg));
                                    }
                                }
                                WireMsg::AggVote(_agg) => {
                                    // For PoC, nothing to do; local author sets justification.
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        // Wait for the next slot.
        futures_timer::Delay::new(slot_duration).await;

        // Determine the parent to build on.
        let info = client.info();
        let parent_hash = info.best_hash;
        let parent_header = match client.header(parent_hash) {
            Ok(Some(h)) => h,
            _ => continue,
        };

        // Build inherents (timestamp from system time).
        let timestamp = TimestampInherent::from_system_time();
        let mut inherent_data = InherentData::new();
        if let Err(e) = timestamp.provide_inherent_data(&mut inherent_data).await {
            warn!(target: "pose", "Failed to provide timestamp inherent: {:?}", e);
            continue;
        }

        // Build PoSE pre-runtime digest: epoch=slot_counter, leader derived from local_id.
        let leader: AccountId = AccountId::unchecked_from(local_id);
        let pre = PreRuntimeDigest { epoch: slot_counter, seed: H256::zero(), leader };
        let mut digests = sp_runtime::Digest::default();
        digests.push(DigestItem::PreRuntime(POSE_ENGINE_ID, pre.encode()));

        // Build the block directly using the block builder, with PoSE pre-runtime digests.
        let mut builder = match client.new_block_at(parent_hash, digests, RecordProof::No) {
            Ok(b) => b,
            Err(e) => {
                warn!(target: "pose", "new_block_at error: {:?}", e);
                continue;
            }
        };

        // Create inherents and include them.
        match builder.create_inherents(inherent_data) {
            Ok(inherents) => {
                for inherent in inherents {
                    if let Err(e) = builder.push(inherent) {
                        warn!(target: "pose", "Failed to push inherent: {:?}", e);
                    }
                }
            }
            Err(e) => {
                warn!(target: "pose", "create_inherents error: {:?}", e);
                continue;
            }
        }

        // Build block and import it.
        let (block, storage_changes, _proof) = match builder.build().map(|b| b.into_inner()) {
            Ok(x) => x,
            Err(e) => {
                warn!(target: "pose", "block build error: {:?}", e);
                continue;
            }
        };

        let mut import_params = sc_consensus::block_import::BlockImportParams::new(
            BlockOrigin::Own,
            block.header().clone(),
        );
        import_params.body = Some(block.extrinsics().to_vec());
        import_params.state_action = sc_consensus::block_import::StateAction::ApplyChanges(
            sc_consensus::block_import::StorageChanges::Changes(storage_changes),
        );
        import_params.fork_choice = Some(sc_consensus::block_import::ForkChoiceStrategy::LongestChain);
        // Emit a PoSE justification once we "commit". For PoC, synthesize quorum bitmap.
        let n = authorities.len().max(1);
        let t = quorum_threshold(n);
        let mut bitmap = Vec::new();
        for i in 0..t {
            let byte = i / 8;
            let bit = i % 8;
            if bitmap.len() <= byte { bitmap.resize(byte + 1, 0); }
            bitmap[byte] |= 1 << bit;
        }
        let j = Justification { round: 0, epoch: slot_counter, agg_sig: [0u8; 96], bitmap };
        import_params.justifications = Some(sp_runtime::Justifications::from((POSE_ENGINE_ID, j.encode())));
        // Mark as finalized to advance finality in this PoC.
        import_params.finalized = true;

        // Gossip: proposal and local votes for this block.
        let prop = Proposal {
            epoch: slot_counter,
            parent: H256::from(parent_hash),
            digest: Vec::new(),
            block_parts: Vec::new(),
            block_hash: H256::from(block.header().hash()),
        };
        broadcast(&*network, &*peers.lock().unwrap(), &protocol, WireMsg::Proposal(prop));
        let prevote = Vote { kind: VoteKind::Prevote, round: 0, epoch: slot_counter, block_hash: H256::from(block.header().hash()), sig_share: vec![], validator_idx: local_index };
        broadcast(&*network, &*peers.lock().unwrap(), &protocol, WireMsg::Vote(prevote));
        let precommit = Vote { kind: VoteKind::Precommit, round: 0, epoch: slot_counter, block_hash: H256::from(block.header().hash()), sig_share: vec![], validator_idx: local_index };
        broadcast(&*network, &*peers.lock().unwrap(), &protocol, WireMsg::Vote(precommit));

        match block_import.import_block(import_params).await {
            Ok(sc_consensus::block_import::ImportResult::Imported(aux)) => {
                let num = block.header().number().clone();
                let hash = block.header().hash();
                info!(target: "pose", "POSE: authored block #{} ({:?}) new_best={}.", num, hash, aux.is_new_best);
            }
            Ok(other) => {
                warn!(target: "pose", "import result: {:?}", other);
            }
            Err(e) => {
                warn!(target: "pose", "import error: {:?}", e);
            }
        }

        // Advance slot counter after each attempt.
        slot_counter = slot_counter.wrapping_add(1);
    }
}
