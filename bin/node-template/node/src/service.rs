//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use futures::FutureExt;
use node_template_runtime::{self, opaque::Block, RuntimeApi};
use sc_client_api::{Backend, BlockBackend};
pub use sc_executor::NativeElseWasmExecutor;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, WarpSyncParams};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use std::{sync::Arc, time::Duration};

use sc_consensus::{
    import_queue::Verifier,
    block_import::{BlockCheckParams, BlockImport, BlockImportParams, ImportResult},
};
use sp_consensus::Error as ConsensusError;
use parity_scale_codec::Decode;
use sp_core::H256;
use sc_service::config::Role;
use sc_service::KeystoreContainer;
use async_trait::async_trait;
use sp_runtime::traits::Header as _;
use sc_consensus_pose::{
    build_import_queue as pose_build_import_queue,
    Justification as PoseJustification, PreRuntimeDigest as PosePreDigest,
    VoteDigest as PoseVoteDigest, POSE_ENGINE_ID,
    pose_vrf, pose_bls,
};
// use std::sync::atomic::{AtomicU64, Ordering};

// Our native executor instance.
pub struct ExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
	/// Only enable the benchmarking host functions when we actually want to benchmark.
	#[cfg(feature = "runtime-benchmarks")]
	type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
	/// Otherwise we only use the default Substrate host functions.
	#[cfg(not(feature = "runtime-benchmarks"))]
	type ExtendHostFunctions = ();

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		node_template_runtime::api::dispatch(method, data)
	}

	fn native_version() -> sc_executor::NativeVersion {
		node_template_runtime::native_version()
	}
}

pub(crate) type FullClient =
	sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

// Minimal no-op verifier and block import to allow the node to boot
// without any consensus engines wired.
struct NoopVerifier;

#[async_trait]
impl Verifier<Block> for NoopVerifier {
    async fn verify(
        &mut self,
        block: BlockImportParams<Block>,
    ) -> Result<BlockImportParams<Block>, String> {
        // Inspect PoSE digests for basic decoding.
        let header = block.header.clone();
        for log in header.digest().logs() {
            match log {
                sp_runtime::DigestItem::PreRuntime(id, data) if *id == POSE_ENGINE_ID => {
                    let _ = PosePreDigest::decode(&mut &data[..]);
                }
                sp_runtime::DigestItem::Consensus(id, data) if *id == POSE_ENGINE_ID => {
                    // Try decoding as VoteDigest or Justification; ignore errors.
                    let mut tmp = &data[..];
                    if PoseVoteDigest::decode(&mut tmp).is_err() {
                        let _ = PoseJustification::decode(&mut &data[..]);
                    }
                }
                _ => {}
            }
        }

        Ok(BlockImportParams::new(block.origin, header))
    }
}

struct NoopBlockImport;

#[async_trait]
impl BlockImport<Block> for NoopBlockImport {
    type Error = ConsensusError;

    async fn check_block(
        &mut self,
        _block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        Ok(ImportResult::imported(false))
    }

    async fn import_block(
        &mut self,
        _block: BlockImportParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        Ok(ImportResult::imported(true))
    }
}

#[allow(clippy::type_complexity)]
pub fn new_partial(
    config: &Configuration,
) -> Result<
    sc_service::PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        sc_consensus::DefaultImportQueue<Block>,
        sc_transaction_pool::FullPool<Block, FullClient>,
        (Option<Telemetry>,),
    >,
    ServiceError,
> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = sc_service::new_native_or_wasm_executor(config);
	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );

    // Use a PoSE import queue with relaxed verifier expectations (accept any epoch/round)
    // and a PoSE justification importer that finalizes blocks when PoSE justifications are seen.
    let just_import = sc_consensus_pose::justification_import::<Block, _, _>(client.clone());
    let import_queue: sc_consensus::DefaultImportQueue<Block> = pose_build_import_queue(
        u64::MAX,
        u64::MAX,
        3,
        Box::new(NoopBlockImport),
        Some(just_import),
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
    );

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (telemetry,),
    })
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (mut telemetry,),
    } = new_partial(&config)?;

    let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);
    // Register PoSE notifications protocol explicitly as "/pose/1"
    {
        let mut pose_set = sc_network::config::NonDefaultSetConfig::new(
            sc_network::types::ProtocolName::from("/pose/1"),
            8 * 1024, // max notification size
        );
        pose_set.allow_non_reserved(64, 64);
        net_config.add_notification_protocol(pose_set);
    }

    // No GRANDPA networking or warp sync.

	let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
        import_queue,
        block_announce_validator_builder: None,
        warp_sync_params: None,
    })?;

	if config.offchain_worker.enabled {
		task_manager.spawn_handle().spawn(
			"offchain-workers-runner",
			"offchain-worker",
			sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
				runtime_api_provider: client.clone(),
				is_validator: config.role.is_authority(),
				keystore: Some(keystore_container.keystore()),
				offchain_db: backend.offchain_storage(),
				transaction_pool: Some(OffchainTransactionPoolFactory::new(
					transaction_pool.clone(),
				)),
				network_provider: network.clone(),
				enable_http_requests: true,
				custom_extensions: |_| vec![],
			})
			.run(client.clone(), task_manager.spawn_handle())
			.boxed(),
		);
	}

    let role = config.role.clone();
    let prometheus_registry = config.prometheus_registry().cloned();

	let rpc_extensions_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();

		Box::new(move |deny_unsafe, _| {
			let deps =
				crate::rpc::FullDeps { client: client.clone(), pool: pool.clone(), deny_unsafe };
			crate::rpc::create_full(deps).map_err(Into::into)
		})
	};

	let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		network: network.clone(),
		client: client.clone(),
		keystore: keystore_container.keystore(),
		task_manager: &mut task_manager,
		transaction_pool: transaction_pool.clone(),
		rpc_builder: rpc_extensions_builder,
		backend,
		system_rpc_tx,
		tx_handler_controller,
		sync_service: sync_service.clone(),
		config,
		telemetry: telemetry.as_mut(),
	})?;

    // Insert dev PoSE keys into keystore (for local/dev networks) based on CLI flags.
    if role.is_authority() {
        if let Some(who) = crate::chain_spec::dev_seed_from_args() {
            ensure_dev_pose_keys(&keystore_container, who);
        }
    }

    network_starter.start_network();
    // After network start, run PoSE authoring loop (PoC)
    let authorities: Vec<H256> = pose_dev_authorities(); // Step 3 will provide real values
    let local_id: H256 = pose_local_id(&keystore_container, role.clone()); // Step 3 will provide real logic
    let slot = std::time::Duration::from_millis(400);

    task_manager.spawn_essential_handle().spawn(
        "pose-consensus",
        None,
        sc_consensus_pose::start::<Block, _, _, _, _>(sc_consensus_pose::StartParams {
            client: client.clone(),
            pool: transaction_pool.clone(),
            block_import: client.clone(),
            authorities,
            local_id,
            slot_duration: slot,
            _phantom: Default::default(),
            network: network.clone(),
        }),
    );

    Ok(task_manager)
}

// Dev helpers for PoSE.
fn pose_dev_authorities() -> Vec<H256> { crate::chain_spec::pose_dev_authorities() }

fn pose_local_id(_keystore: &KeystoreContainer, role: Role) -> H256 {
    // Derive from dev name if validator flags are used; otherwise use "//Full".
    use sp_core::blake2_256;
    let tag = if role.is_authority() { crate::chain_spec::dev_seed_from_args().unwrap_or("//Dave") } else { "//Full" };
    H256::from(blake2_256(tag.as_bytes()))
}

fn dev_tag_from_args() -> Option<&'static str> {
    for arg in std::env::args() {
        let a = arg.to_ascii_lowercase();
        if a == "--alice" { return Some("//Alice") }
        if a == "--bob" { return Some("//Bob") }
        if a == "--charlie" { return Some("//Charlie") }
        if a == "--dave" { return Some("//Dave") }
    }
    None
}

fn ensure_dev_pose_keys(keystore: &KeystoreContainer, who: &str) {
    // Only insert if not present. Generate from dev seed for determinism.
    let vrf = pose_vrf::Pair::from_string(who, None).expect("dev key");
    let bls = pose_bls::Pair::from_string(who, None).expect("dev key");
    let store = keystore.keystore();
    let vrf_pub = vrf.public();
    let bls_pub = bls.public();

    let need_vrf = !store.has_keys(&[(vrf_pub.as_ref().to_vec(), pose_vrf::KEY_TYPE)]);
    let need_bls = !store.has_keys(&[(bls_pub.as_ref().to_vec(), pose_bls::KEY_TYPE)]);

    if need_vrf {
        let _ = store.insert(pose_vrf::KEY_TYPE, &who.to_string(), vrf_pub.as_ref());
    }
    if need_bls {
        let _ = store.insert(pose_bls::KEY_TYPE, &who.to_string(), bls_pub.as_ref());
    }
}
