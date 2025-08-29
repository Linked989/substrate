use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use sc_client_api::backend::{Backend as ClientBackend, Finalizer};
use sc_consensus::block_import::JustificationImport;
use sp_blockchain::HeaderBackend;
use sp_consensus::Error as ConsensusError;
use sp_runtime::{traits::Block as BlockT, Justification, NumberFor};

/// Minimal PoSE justification import: finalizes blocks when a justification is provided.
pub struct PoseJustificationImport<Client, Block, CB> {
    pub client: Arc<Client>,
    pub(crate) _m: PhantomData<(Block, CB)>,
}

#[async_trait]
impl<B, C, CB> JustificationImport<B> for PoseJustificationImport<C, B, CB>
where
    B: BlockT,
    C: HeaderBackend<B> + Finalizer<B, CB> + Send + Sync + 'static,
    CB: ClientBackend<B> + 'static,
{
    type Error = ConsensusError;

    async fn on_start(&mut self) -> Vec<(B::Hash, NumberFor<B>)> { Vec::new() }

    async fn import_justification(
        &mut self,
        hash: B::Hash,
        _number: NumberFor<B>,
        justification: Justification,
    ) -> Result<(), Self::Error> {
        // TODO: verify BLS aggregate + quorum bitmap from justification
        self.client
            .finalize_block(hash, Some(justification), true)
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?;
        Ok(())
    }
}

