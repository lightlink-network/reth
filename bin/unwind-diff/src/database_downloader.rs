//! Database-based downloader implementation for reading blocks from a database instead of P2P.
//!
//! This module provides `DatabaseHeaderDownloader` and `DatabaseBodyDownloader` which implement
//! the `HeaderDownloader` and `BodyDownloader` traits respectively. These can be used with
//! reth's sync stages (HeaderStage and BodyStage) to sync from a local database instead of
//! downloading from the network.
//!
//! # Example
//!
//! ```ignore
//! use reth_stages::stages::{HeaderStage, BodyStage};
//! use unwind_diff::database_downloader::{DatabaseHeaderDownloader, DatabaseBodyDownloader};
//!
//! // Create downloaders that read from a snapshot database
//! let header_downloader = DatabaseHeaderDownloader::new(snapshot_factory.clone());
//! let body_downloader = DatabaseBodyDownloader::new(snapshot_factory);
//!
//! // Use them with stages
//! let header_stage = HeaderStage::new(provider, header_downloader, tip_rx, etl_config);
//! let body_stage = BodyStage::new(body_downloader);
//! ```

use alloy_primitives::BlockNumber;
use futures::Stream;
use reth_db::DatabaseEnv;
use reth_ethereum::node::EthereumNode;
use reth_network_p2p::{
    bodies::{downloader::BodyDownloader, response::BlockResponse},
    error::DownloadResult,
    headers::{
        downloader::{HeaderDownloader, SyncTarget},
        error::HeadersDownloaderResult,
    },
};
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::{AlloyBlockHeader, SealedHeader};
use reth_provider::{
    BlockNumReader, BlockReader, HeaderProvider, ProviderFactory, TransactionVariant,
};
use std::{
    ops::RangeInclusive,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tracing::debug;

type EthHeader = reth_primitives::Header;
type EthBlock = reth_primitives::Block;

/// A downloader that reads headers from a database instead of downloading from the network.
pub struct DatabaseHeaderDownloader {
    /// The provider factory for accessing the database.
    provider_factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
    /// The current local head block number.
    local_head: Option<BlockNumber>,
    /// The target block to sync to.
    sync_target: Option<BlockNumber>,
    /// The batch size for yielding headers.
    batch_size: usize,
    /// Current position in the sync process.
    current_position: Option<BlockNumber>,
}

impl DatabaseHeaderDownloader {
    /// Create a new database header downloader.
    pub fn new(
        provider_factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
    ) -> Self {
        Self {
            provider_factory,
            local_head: None,
            sync_target: None,
            batch_size: 1000,
            current_position: None,
        }
    }

    /// Get the next batch of headers to yield.
    /// Headers are returned in REVERSE order (from high to low block numbers)
    /// to match the expectations of the HeaderStage.
    fn get_next_headers(&mut self) -> Option<Vec<SealedHeader<EthHeader>>> {
        let local_head = self.local_head?;
        let sync_target = self.sync_target?;

        if local_head >= sync_target {
            debug!(target: "database_downloader::header", "Sync complete: local_head {} >= sync_target {}", local_head, sync_target);
            return None;
        }

        // Start from sync_target and work backwards
        let end = self.current_position.unwrap_or(sync_target);
        if end <= local_head {
            return None;
        }

        let start = end.saturating_sub(self.batch_size as u64 - 1).max(local_head + 1);

        debug!(target: "database_downloader::header", "Fetching headers from {} to {} (will return in reverse order)", start, end);

        // Read headers from database
        let provider = match self.provider_factory.provider() {
            Ok(provider) => provider,
            Err(e) => {
                debug!(target: "database_downloader::header", "Failed to get provider: {}", e);
                return None;
            }
        };

        let mut headers = Vec::new();
        // Collect headers in order first
        for block_num in start..=end {
            match provider.sealed_header(block_num) {
                Ok(Some(header)) => headers.push(header),
                Ok(None) => {
                    debug!(target: "database_downloader::header", "Header not found for block {}", block_num);
                    break;
                }
                Err(e) => {
                    debug!(target: "database_downloader::header", "Failed to read header {}: {}", block_num, e);
                    break;
                }
            }
        }

        if !headers.is_empty() {
            // Reverse headers to return them in descending order (high to low)
            headers.reverse();

            debug!(
                target: "database_downloader::header",
                "Returning {} headers in reverse order: {} -> {}",
                headers.len(),
                headers.first().unwrap().number(),
                headers.last().unwrap().number()
            );

            // Update position for next batch (move backwards)
            self.current_position = Some(headers.last().unwrap().number() - 1);
            Some(headers)
        } else {
            None
        }
    }
}

impl Stream for DatabaseHeaderDownloader {
    type Item = HeadersDownloaderResult<Vec<SealedHeader<EthHeader>>, EthHeader>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(headers) = self.get_next_headers() {
            Poll::Ready(Some(Ok(headers)))
        } else {
            Poll::Ready(None)
        }
    }
}

impl HeaderDownloader for DatabaseHeaderDownloader {
    type Header = EthHeader;

    fn update_local_head(&mut self, head: SealedHeader<Self::Header>) {
        debug!(target: "database_downloader::header", "Updating local head to block {}", head.number());
        self.local_head = Some(head.number());
        // Reset position when local head changes (will start from sync_target on next poll)
        self.current_position = None;
    }

    fn update_sync_target(&mut self, target: SyncTarget) {
        let target_num = match target {
            SyncTarget::Tip(hash) => {
                // Try to resolve hash to number
                if let Ok(provider) = self.provider_factory.provider() {
                    if let Ok(Some(num)) = provider.block_number(hash) {
                        num
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            }
            SyncTarget::Gap(gap) => gap.block.number.saturating_sub(1),
            SyncTarget::TipNum(num) => num,
        };

        debug!(target: "database_downloader::header", "Updating sync target to block {}", target_num);
        self.sync_target = Some(target_num);
    }

    fn set_batch_size(&mut self, limit: usize) {
        debug!(target: "database_downloader::header", "Setting batch size to {}", limit);
        self.batch_size = limit;
    }
}

/// A downloader that reads bodies from a database instead of downloading from the network.
pub struct DatabaseBodyDownloader {
    /// The provider factory for accessing the database.
    provider_factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
    /// Range of blocks to download bodies for.
    body_download_range: Option<RangeInclusive<BlockNumber>>,
    /// Current position in the download process.
    current_position: Option<BlockNumber>,
    /// The batch size for yielding bodies.
    batch_size: usize,
}

impl DatabaseBodyDownloader {
    /// Create a new database body downloader.
    pub fn new(
        provider_factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
    ) -> Self {
        Self {
            provider_factory,
            body_download_range: None,
            current_position: None,
            batch_size: 100,
        }
    }

    /// Get the next batch of bodies to yield.
    fn get_next_bodies(&mut self) -> Option<Vec<BlockResponse<EthBlock>>> {
        let range = self.body_download_range.as_ref()?;

        let start = self.current_position.unwrap_or(*range.start());
        if start > *range.end() {
            return None;
        }

        let end = std::cmp::min(start + self.batch_size as u64 - 1, *range.end());

        debug!(target: "database_downloader::body", "Fetching bodies from {} to {}", start, end);

        // Read blocks from database
        let provider = match self.provider_factory.provider() {
            Ok(provider) => provider,
            Err(e) => {
                debug!(target: "database_downloader::body", "Failed to get provider: {}", e);
                return None;
            }
        };

        let mut responses = Vec::new();
        for block_num in start..=end {
            match provider.sealed_block_with_senders(block_num.into(), TransactionVariant::WithHash)
            {
                Ok(Some(recovered_block)) => {
                    // RecoveredBlock derefs to SealedBlock, so we need to clone the inner block
                    let sealed_block = (*recovered_block).clone();
                    responses.push(BlockResponse::Full(sealed_block));
                }
                Ok(None) => {
                    debug!(target: "database_downloader::body", "Block not found for number {}", block_num);
                    break;
                }
                Err(e) => {
                    debug!(target: "database_downloader::body", "Failed to read block {}: {}", block_num, e);
                    break;
                }
            }
        }

        if !responses.is_empty() {
            // Update position for next batch
            self.current_position = Some(end + 1);
            Some(responses)
        } else {
            None
        }
    }
}

impl Stream for DatabaseBodyDownloader {
    type Item = DownloadResult<Vec<BlockResponse<EthBlock>>>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(bodies) = self.get_next_bodies() {
            Poll::Ready(Some(Ok(bodies)))
        } else {
            Poll::Ready(None)
        }
    }
}

impl BodyDownloader for DatabaseBodyDownloader {
    type Block = EthBlock;

    fn set_download_range(&mut self, range: RangeInclusive<BlockNumber>) -> DownloadResult<()> {
        debug!(target: "database_downloader::body", "Setting body download range to {:?}", range);
        self.body_download_range = Some(range);
        self.current_position = None;
        Ok(())
    }
}
