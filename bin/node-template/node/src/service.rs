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
    import_queue::{BasicQueue, Verifier},
    block_import::{BlockCheckParams, BlockImport, BlockImportParams, ImportResult},
};
use sp_consensus::Error as ConsensusError;
use parity_scale_codec::Decode;
use sc_consensus_pose::{
    build_import_queue as pose_build_import_queue, peers_set_config as pose_peers_set,
    Justification as PoseJustification, PreRuntimeDigest as PosePreDigest,
    VoteDigest as PoseVoteDigest, POSE_ENGINE_ID, Pacemaker, PacemakerConfig,
};
use std::sync::atomic::{AtomicU64, Ordering};
use sp_keystore::SyncCryptoStore;
use sp_keyring::Sr25519Keyring;

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

#[async_trait::async_trait]
impl Verifier<Block> for NoopVerifier {
    async fn verify(
        &mut self,
        block: BlockImportParams<Block>,
    ) -> Result<BlockImportParams<Block>, String> {
        // Inspect PoSE digests for basic decoding.
        let header = block.header.clone();
        for log in header.digest().logs() {
            match log {
                sp_runtime::DigestItem::PreRuntime(id, data) if id == &POSE_ENGINE_ID => {
                    let _ = PosePreDigest::decode(&mut &data[..]);
                }
                sp_runtime::DigestItem::Consensus(id, data) if id == &POSE_ENGINE_ID => {
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

#[async_trait::async_trait]
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

    // Use a minimal BasicQueue with no-op import to allow the node to start.
    // Build PoSE import queue with relaxed verifier expectations (accept any epoch/round)
    let import_queue: sc_consensus::DefaultImportQueue<Block> = pose_build_import_queue(
        u64::MAX,
        u64::MAX,
        3,
        Box::new(NoopBlockImport),
        None,
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
    // Register PoSE notifications protocol
    net_config.add_notification_protocol(pose_peers_set());

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

    // Instantiate PoSE proposer (ordering helper) and pacemaker.
    let _proposer = sc_consensus_pose::PoSEProposer;
    // PoSE consensus task (prototype): maintains a local epoch counter and timeouts.
    let epoch_counter = Arc::new(AtomicU64::new(0));
    let _epoch_counter_for_rpc = epoch_counter.clone();
    let mut pacemaker = Pacemaker::new(PacemakerConfig::default());

    // Inject PoSE dev keys into keystore (Alice, Bob, Charlie) for PoC.
    {
        let keystore = keystore_container.keystore();
        for who in [Sr25519Keyring::Alice, Sr25519Keyring::Bob, Sr25519Keyring::Charlie] {
            let suri = format!("//{}", who);
            let _ = sp_keystore::SyncCryptoStore::sr25519_generate_new(
                &*keystore,
                sc_consensus_pose::pose_vrf::KEY_TYPE,
                Some(&suri),
            );
            let _ = sp_keystore::SyncCryptoStore::ed25519_generate_new(
                &*keystore,
                sc_consensus_pose::pose_bls::KEY_TYPE,
                Some(&suri),
            );
        }
    }
    task_manager.spawn_handle().spawn_blocking(
        "pose-consensus",
        None,
        {
            move || {
                loop {
                    // Placeholder consensus loop; in a full implementation this would:
                    // - run leader election per epoch
                    // - gossip proposals and collect votes
                    // - on commit, submit block import with PoSE justification
                    std::thread::sleep(pacemaker.proposal_timeout());
                    let _ = epoch_counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        },
    );

    network_starter.start_network();
    Ok(task_manager)
}
