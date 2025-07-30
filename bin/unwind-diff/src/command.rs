use alloy_primitives::{BlockNumber, B256};
use clap::Parser;
use eyre::{eyre, Result};
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_runner::CliContext;
use reth_consensus::noop::NoopConsensus;
use reth_db::{init_db, open_db_read_only, tables_to_generic, DatabaseEnv};
use reth_db_api::{
    cursor::DbCursorRO, database::Database, table::Table, transaction::DbTx, Tables,
};
use reth_db_common::init::init_genesis;
use reth_ethereum::{
    node::{EthEvmConfig, EthereumNode},
    provider::{providers::ReadOnlyConfig, BlockHashReader, BlockNumReader},
};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_node_core::args::LogArgs;
use reth_provider::{providers::StaticFileProvider, ProviderFactory, StaticFileProviderFactory};
use reth_tracing::FileWorkerGuard;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use tracing::{debug, error, info, warn};

#[derive(Debug, Parser)]
#[command(author, version, about = "Performs unwind diffs between database states")]
pub struct UnwindDiffCommand {
    /// The chain this node is running.
    #[arg(
        long,
        value_name = "CHAIN_OR_PATH",
        long_help = EthereumChainSpecParser::help_message(),
        default_value = EthereumChainSpecParser::SUPPORTED_CHAINS[0],
        value_parser = EthereumChainSpecParser::parser(),
        global = true
    )]
    pub chain: Arc<<EthereumChainSpecParser as ChainSpecParser>::ChainSpec>,

    /// Path to baseline datadir
    #[arg(long, value_name = "PATH")]
    pub datadir_baseline: PathBuf,

    /// Path to unwind datadir
    #[arg(long, value_name = "PATH")]
    pub datadir_unwind: PathBuf,

    /// Path to snapshot datadir (full archive node)
    #[arg(long, value_name = "PATH")]
    pub datadir_snapshot: PathBuf,

    /// Start from this block number (inclusive)
    #[arg(long)]
    pub from: Option<BlockNumber>,

    /// Process up to this block number (inclusive)
    #[arg(long)]
    pub to: Option<BlockNumber>,

    /// Output directory for diff results
    #[arg(long, default_value = "./unwind-results")]
    pub output: PathBuf,

    /// Number of blocks to sync in each iteration
    #[arg(long, default_value = "1")]
    pub step: BlockNumber,

    #[command(flatten)]
    logs: LogArgs,
}

impl UnwindDiffCommand {
    pub async fn execute(self, _ctx: CliContext) -> Result<()> {
        // Initialize tracing
        let _guard = self.init_tracing()?;

        info!("Starting unwind-diff process");

        // Set up a shutdown flag for graceful shutdown
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        // Spawn a task to listen for ctrl-c
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
            println!("\n⚠️  Received interrupt signal, shutting down gracefully...");
            shutdown_clone.store(true, Ordering::Relaxed);
        });

        // Open snapshot database to read blocks
        let snapshot_factory = EthereumNode::provider_factory_builder().open_read_only(
            self.chain.clone(),
            ReadOnlyConfig::from_datadir(self.datadir_snapshot.clone()),
        )?;
        let snapshot_provider = snapshot_factory.provider()?;

        // Get block range
        let best_block = snapshot_provider.best_block_number()?;
        let from_block = self.from.unwrap_or(0);
        let to_block = self.to.unwrap_or(best_block);

        info!(
            "Processing blocks from {} to {} with step {} (snapshot best: {})",
            from_block, to_block, self.step, best_block
        );

        // Validate that snapshot has enough blocks for the step size
        let required_blocks = to_block + self.step;
        if required_blocks > best_block {
            return Err(eyre!(
                "Snapshot doesn't have enough blocks. Required: {} (to_block {} + step {}), Available: {}",
                required_blocks,
                to_block,
                self.step,
                best_block
            ));
        }

        // Create output directory
        fs::create_dir_all(&self.output)?;

        // Check and unwind baseline and unwind datadirs if they're synced higher than from_block
        info!("Checking if datadirs need to be unwound to starting block {}", from_block);

        // Check baseline datadir
        {
            let baseline_factory = self.create_provider_factory(&self.datadir_baseline).await?;
            let provider = baseline_factory.provider()?;
            let current_block = provider.best_block_number().unwrap_or(0);
            drop(provider);

            if current_block > from_block {
                info!(
                    "Baseline datadir is at block {}, unwinding to {}",
                    current_block, from_block
                );
                self.unwind_to_block(baseline_factory, from_block).await?;
            } else {
                info!("Baseline datadir is at block {}, no unwind needed", current_block);
            }
        }

        // Check unwind datadir
        {
            let unwind_factory = self.create_provider_factory(&self.datadir_unwind).await?;
            let provider = unwind_factory.provider()?;
            let current_block = provider.best_block_number().unwrap_or(0);
            drop(provider);

            if current_block > from_block {
                info!("Unwind datadir is at block {}, unwinding to {}", current_block, from_block);
                self.unwind_to_block(unwind_factory, from_block).await?;
            } else {
                info!("Unwind datadir is at block {}, no unwind needed", current_block);
            }
        }

        // Process blocks in steps
        let total_blocks = to_block - from_block + 1;
        let mut current_block = from_block;
        let mut iteration = 0;

        while current_block <= to_block {
            // Check for shutdown signal
            if shutdown.load(Ordering::Relaxed) {
                println!("🛑 Shutdown requested, stopping at block {}", current_block);
                return Err(eyre!("Process interrupted by user"));
            }

            let block_start_time = Instant::now();

            // Calculate the end block for this step (don't exceed to_block)
            let step_end_block = (current_block + self.step - 1).min(to_block);

            iteration += 1;
            println!(
                "🔄 Processing iteration {} - blocks {} to {} (step size: {})...",
                iteration, current_block, step_end_block, self.step
            );

            // Create factories for this iteration
            let baseline_factory = self.create_provider_factory(&self.datadir_baseline).await?;
            let unwind_factory = self.create_provider_factory(&self.datadir_unwind).await?;

            // Step 1: Sync baseline to end of this step
            info!("Step 1: Syncing baseline to block {}", step_end_block);
            println!("  📊 Step 1/4: Syncing baseline to block {}...", step_end_block);
            {
                let provider = baseline_factory.provider()?;
                let current = provider.best_block_number().unwrap_or(0);
                drop(provider);

                if current < step_end_block {
                    self.sync_with_pipeline(
                        step_end_block,
                        snapshot_factory.clone(),
                        baseline_factory.clone(),
                    )
                    .await?;
                } else {
                    info!("Baseline already at or past block {}, skipping sync", step_end_block);
                }
            }

            // Step 2: Sync unwind datadir to 2*step blocks ahead
            let unwind_sync_target = step_end_block + self.step;
            info!("Step 2: Syncing unwind datadir to block {}", unwind_sync_target);
            println!(
                "  📈 Step 2/4: Syncing unwind datadir to block {} (2x step)...",
                unwind_sync_target
            );
            {
                let provider = unwind_factory.provider()?;
                let current = provider.best_block_number().unwrap_or(0);
                drop(provider);

                if current < unwind_sync_target {
                    self.sync_with_pipeline(
                        unwind_sync_target,
                        snapshot_factory.clone(),
                        unwind_factory.clone(),
                    )
                    .await?;
                } else {
                    info!(
                        "Unwind datadir already at or past block {}, skipping sync",
                        unwind_sync_target
                    );
                }
            }

            // Step 3: Unwind back to step_end_block
            info!("Step 3: Unwinding to block {}", step_end_block);
            println!(
                "  ⏪ Step 3/4: Unwinding {} blocks back to block {}...",
                self.step, step_end_block
            );
            {
                self.unwind_to_block(unwind_factory.clone(), step_end_block).await?;
            }

            // Drop the factories to release database locks before performing diff
            drop(baseline_factory);
            drop(unwind_factory);

            // Step 4: Perform diff (both databases are now at step_end_block)
            println!("  🔍 Step 4/4: Comparing databases at block {}...", step_end_block);
            let output_dir = self.output.join(format!("{}-{}", current_block, step_end_block));
            self.perform_diff(&self.datadir_baseline, &self.datadir_unwind, &output_dir)?;

            let block_duration = block_start_time.elapsed();
            println!(
                "  ✅ Completed {} blocks (#{} to #{}) in {:.2?}\n",
                step_end_block - current_block + 1,
                current_block,
                step_end_block,
                block_duration
            );
            info!(
                "Completed processing blocks {} to {} in {:?}",
                current_block, step_end_block, block_duration
            );

            // Move to next step
            current_block = step_end_block + 1;
        }

        println!("\n🎉 All {} blocks processed successfully!", total_blocks);
        info!("All blocks processed successfully!");
        Ok(())
    }

    /// Sync a target database to a specific block using a full pipeline with database downloaders.
    ///
    /// This method creates a complete sync pipeline with all stages, using the DatabaseDownloaders
    /// to read blocks from the snapshot database instead of downloading from the network.
    async fn sync_with_pipeline(
        &self,
        target_block: BlockNumber,
        snapshot_factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
        target_factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
    ) -> Result<()> {
        use crate::database_downloader::{DatabaseBodyDownloader, DatabaseHeaderDownloader};
        use reth_config::config::StageConfig;
        use reth_network_p2p::headers::downloader::{HeaderDownloader, SyncTarget};
        use reth_provider::HeaderProvider;
        use reth_prune_types::PruneModes;
        use reth_stages::{sets::DefaultStages, Pipeline};
        use reth_static_file::StaticFileProducer;
        use tokio::sync::watch;

        info!("Syncing to block {} using full pipeline", target_block);

        // Check current state of target database
        let provider = target_factory.provider()?;
        let best_block = provider.best_block_number();
        let current_block = best_block.clone().unwrap_or(0);
        let last_block = provider.last_block_number()?;
        let local_head = provider.sealed_header(current_block)?;
        info!(
            "Target database state - current_block: {}, last_block: {}, target: {}",
            current_block, last_block, target_block,
        );

        drop(provider);

        if current_block >= target_block {
            info!(
                "Target database already at or past block {} (current: {})",
                target_block, current_block
            );
            return Ok(());
        }

        // Create EVM config and consensus
        let evm_config = EthEvmConfig::new(self.chain.clone());
        let consensus = Arc::new(NoopConsensus::default());

        // Create database downloaders
        let mut header_downloader = DatabaseHeaderDownloader::new(snapshot_factory.clone());
        let body_downloader = DatabaseBodyDownloader::new(snapshot_factory.clone());

        // Set up the header downloader
        if let Some(head) = local_head {
            header_downloader.update_local_head(head);
        }
        header_downloader.update_sync_target(SyncTarget::TipNum(target_block));

        // Create tip channel
        let (tip_tx, tip_rx) = watch::channel(B256::ZERO);

        // Default configurations
        let stage_config = StageConfig::default();
        let prune_modes = PruneModes::none();

        // Build the pipeline with DefaultStages
        let stages = DefaultStages::new(
            target_factory.clone(),
            tip_rx,
            consensus,
            header_downloader,
            body_downloader,
            evm_config,
            stage_config,
            prune_modes.clone(),
            None, // era_import_source
        );

        let static_file_producer = StaticFileProducer::new(target_factory.clone(), prune_modes);

        let mut pipeline = Pipeline::builder()
            .with_tip_sender(tip_tx)
            .with_max_block(target_block)
            .add_stages(stages)
            .build(target_factory.clone(), static_file_producer);

        info!("Running pipeline to sync to block {}", target_block);

        // Run the pipeline
        tokio::select! {
            res = pipeline.run() => {
                res?;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Interrupted, stopping pipeline...");
                return Err(eyre!("Sync interrupted"));
            }
        }

        info!("Successfully synced to block {} using pipeline", target_block);
        Ok(())
    }

    fn perform_diff(
        &self,
        baseline_dir: &Path,
        unwind_dir: &Path,
        output_dir: &Path,
    ) -> Result<()> {
        info!(
            "Performing database diff between {} and {}",
            baseline_dir.display(),
            unwind_dir.display()
        );

        fs::create_dir_all(output_dir)?;

        // Open both databases
        let baseline_db = open_db_read_only(baseline_dir.join("db"), Default::default())?;
        let unwind_db = open_db_read_only(unwind_dir.join("db"), Default::default())?;

        // Tables to ignore during diff
        let ignored_tables = [
            Tables::ChainState,
            Tables::StageCheckpoints,
            Tables::StageCheckpointProgresses,
            Tables::PruneCheckpoints,
            // Not expected to be different, but shouldn't hurt anything
            Tables::TransactionSenders,
            Tables::Bytecodes,
        ];

        let mut has_differences = false;
        let mut tables_with_diffs = Vec::new();

        // Diff all tables
        for table in Tables::ALL {
            // Skip ignored tables
            if ignored_tables.contains(table) {
                debug!("Skipping ignored table: {}", table.name());
                continue;
            }

            let baseline_tx = baseline_db.tx()?;
            let unwind_tx = unwind_db.tx()?;

            let has_diff = tables_to_generic!(table, |T| {
                self.diff_table::<T>(baseline_tx, unwind_tx, output_dir)
            })?;

            if has_diff {
                has_differences = true;
                tables_with_diffs.push(table.name());
            }
        }

        if has_differences {
            error!("Found differences in non-ignored tables: {:?}", tables_with_diffs);
            error!("Database diff failed - see results in {}", output_dir.display());
            return Err(eyre!("Database diff found differences in tables: {:?}", tables_with_diffs));
        }

        info!("Database diff completed successfully - no differences found in non-ignored tables");
        Ok(())
    }

    fn diff_table<T: Table>(
        &self,
        baseline_tx: impl DbTx,
        unwind_tx: impl DbTx,
        output_dir: &Path,
    ) -> Result<bool>
    where
        T::Key: Clone,
        T::Value: PartialEq + Clone,
    {
        let mut baseline_cursor = baseline_tx.cursor_read::<T>()?;
        let mut unwind_cursor = unwind_tx.cursor_read::<T>()?;

        let mut baseline_only = Vec::new();
        let mut unwind_only = Vec::new();
        let mut different = Vec::new();

        // Walk both cursors and collect differences
        let mut baseline_walker = baseline_cursor.walk(None)?;
        let mut unwind_walker = unwind_cursor.walk(None)?;

        let mut baseline_entry = baseline_walker.next();
        let mut unwind_entry = unwind_walker.next();

        loop {
            match (&baseline_entry, &unwind_entry) {
                (Some(Ok((b_key, b_val))), Some(Ok((u_key, u_val)))) => match b_key.cmp(u_key) {
                    std::cmp::Ordering::Less => {
                        baseline_only.push((b_key.clone(), b_val.clone()));
                        baseline_entry = baseline_walker.next();
                    }
                    std::cmp::Ordering::Greater => {
                        unwind_only.push((u_key.clone(), u_val.clone()));
                        unwind_entry = unwind_walker.next();
                    }
                    std::cmp::Ordering::Equal => {
                        if b_val != u_val {
                            different.push((b_key.clone(), b_val.clone(), u_val.clone()));
                        }
                        baseline_entry = baseline_walker.next();
                        unwind_entry = unwind_walker.next();
                    }
                },
                (Some(Ok((key, val))), None) => {
                    baseline_only.push((key.clone(), val.clone()));
                    baseline_entry = baseline_walker.next();
                }
                (None, Some(Ok((key, val)))) => {
                    unwind_only.push((key.clone(), val.clone()));
                    unwind_entry = unwind_walker.next();
                }
                (Some(Err(e)), _) => {
                    error!("Error walking baseline table {}: {}", T::NAME, e);
                    baseline_entry = baseline_walker.next();
                }
                (_, Some(Err(e))) => {
                    error!("Error walking unwind table {}: {}", T::NAME, e);
                    unwind_entry = unwind_walker.next();
                }
                (None, None) => break,
            }
        }

        // Check if there are differences
        let has_differences =
            !baseline_only.is_empty() || !unwind_only.is_empty() || !different.is_empty();

        // Write results if there are differences
        if has_differences {
            warn!(
                "Found differences in table {}: baseline_only={}, unwind_only={}, different_values={}",
                T::NAME,
                baseline_only.len(),
                unwind_only.len(),
                different.len()
            );

            let table_file = output_dir.join(format!("{}.diff", T::NAME));
            let mut file = File::create(table_file)?;

            writeln!(file, "Table: {}", T::NAME)?;
            writeln!(file, "=")?;
            writeln!(file, "Baseline only: {}", baseline_only.len())?;
            writeln!(file, "Unwind only: {}", unwind_only.len())?;
            writeln!(file, "Different values: {}", different.len())?;
            writeln!(file)?;

            if !baseline_only.is_empty() {
                writeln!(file, "Entries only in baseline:")?;
                for (key, val) in &baseline_only[..baseline_only.len().min(10)] {
                    writeln!(file, "  {:?} => {:?}", key, val)?;
                }
                if baseline_only.len() > 10 {
                    writeln!(file, "  ... and {} more", baseline_only.len() - 10)?;
                }
                writeln!(file)?;
            }

            if !unwind_only.is_empty() {
                writeln!(file, "Entries only in unwind:")?;
                for (key, val) in &unwind_only[..unwind_only.len().min(10)] {
                    writeln!(file, "  {:?} => {:?}", key, val)?;
                }
                if unwind_only.len() > 10 {
                    writeln!(file, "  ... and {} more", unwind_only.len() - 10)?;
                }
                writeln!(file)?;
            }

            if !different.is_empty() {
                writeln!(file, "Entries with different values:")?;
                for (key, baseline_val, unwind_val) in &different[..different.len().min(10)] {
                    writeln!(file, "  Key: {:?}", key)?;
                    writeln!(file, "    Baseline: {:?}", baseline_val)?;
                    writeln!(file, "    Unwind:   {:?}", unwind_val)?;
                }
                if different.len() > 10 {
                    writeln!(file, "  ... and {} more", different.len() - 10)?;
                }
            }
        } else {
            debug!("No differences found in table {}", T::NAME);
        }

        Ok(has_differences)
    }

    /// Create a provider factory for the given datadir.
    async fn create_provider_factory(
        &self,
        datadir: &Path,
    ) -> Result<ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>> {
        let db_path = datadir.join("db");
        let static_files_path = datadir.join("static_files");

        // Initialize database with write access
        let db = Arc::new(init_db(&db_path, Default::default())?);

        // Create static file provider with read-write access
        let static_file_provider = StaticFileProvider::read_write(&static_files_path)?;

        // Create the provider factory
        type Adapter = NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>;
        let provider_factory =
            ProviderFactory::<Adapter>::new(db.clone(), self.chain.clone(), static_file_provider);

        // Initialize genesis if the database is empty
        let provider = provider_factory.provider()?;
        let best_block = provider.best_block_number().unwrap_or(0);

        if best_block == 0 {
            let needs_genesis = provider.block_hash(0)?.is_none();
            drop(provider);

            if needs_genesis {
                info!("Initializing empty database with genesis block at {}", datadir.display());
                let genesis_hash = init_genesis(&provider_factory)?;
                info!("Initialized genesis with hash: {}", genesis_hash);
            }
        } else {
            drop(provider);
        }

        Ok(provider_factory)
    }

    /// Unwind a database to a specific block height using a full unwind pipeline.
    async fn unwind_to_block(
        &self,
        factory: ProviderFactory<NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>>,
        target_block: BlockNumber,
    ) -> Result<()> {
        use reth_config::config::StageConfig;
        use reth_downloaders::{
            bodies::noop::NoopBodiesDownloader, headers::noop::NoopHeaderDownloader,
        };
        use reth_exex::ExExManagerHandle;
        use reth_prune_types::PruneModes;
        use reth_stages::{
            sets::DefaultStages, stages::ExecutionStage, ExecutionStageThresholds, Pipeline,
            StageSet,
        };
        use reth_static_file::StaticFileProducer;
        use tokio::sync::watch;

        let provider = factory.provider()?;
        let current_block = provider.best_block_number()?;

        if current_block <= target_block {
            info!(
                "Database already at or below target block (current: {}, target: {})",
                current_block, target_block
            );
            return Ok(());
        }

        let highest_static_file_block = factory
            .static_file_provider()
            .get_highest_static_files()
            .max_block_num()
            .filter(|highest_static_file_block| *highest_static_file_block > target_block);
        drop(provider);

        info!("Unwinding from block {} to block {} using pipeline", current_block, target_block);

        // Build an unwind pipeline with all necessary stages
        let evm_config = EthEvmConfig::new(self.chain.clone());
        let consensus = Arc::new(NoopConsensus::default());
        let (tip_tx, tip_rx) = watch::channel(B256::ZERO);

        let stage_config = StageConfig::default();
        let prune_modes = PruneModes::none();

        // Build the pipeline with all stages using DefaultStages
        let stages = DefaultStages::new(
            factory.clone(),
            tip_rx,
            consensus.clone(),
            NoopHeaderDownloader::default(),
            NoopBodiesDownloader::default(),
            evm_config.clone(),
            stage_config.clone(),
            prune_modes.clone(),
            None, // era_import_source
        )
        .set(ExecutionStage::new(
            evm_config,
            Arc::new(NoopConsensus::default()),
            ExecutionStageThresholds {
                max_blocks: None,
                max_changes: None,
                max_cumulative_gas: None,
                max_duration: None,
            },
            stage_config.execution_external_clean_threshold(),
            ExExManagerHandle::empty(),
        ));

        let static_file_producer = StaticFileProducer::new(factory.clone(), prune_modes);

        let mut pipeline = Pipeline::builder()
            .with_tip_sender(tip_tx)
            .add_stages(stages)
            .build(factory.clone(), static_file_producer);

        // Move applicable data from database to static files if needed
        if highest_static_file_block.is_some() {
            pipeline.move_to_static_files()?;
        }

        // Perform the unwind
        pipeline.unwind(target_block, None)?;

        info!("Successfully unwound to block {}", target_block);
        Ok(())
    }

    /// Initializes tracing with the configured options.
    ///
    /// If file logging is enabled, this function returns a guard that must be kept alive to ensure
    /// that all logs are flushed to disk.
    pub(crate) fn init_tracing(&self) -> Result<Option<FileWorkerGuard>> {
        let guard = self.logs.init_tracing()?;
        Ok(guard)
    }
}
