//! Example demonstrating how to access the Engine API instance during construction.
//!
//! Run with
//!
//! ```sh
//! cargo run -p example-engine-api-access
//! ```

use op_alloy_network::Optimism;
use reth_db::test_utils::create_test_rw_db;
use reth_node_builder::{
    rpc::BasicEngineValidatorBuilder, EngineApiExt, FullNodeComponents, NodeBuilder, NodeConfig,
};
use reth_optimism_chainspec::BASE_MAINNET;
use reth_optimism_node::{
    args::RollupArgs, node::OpEngineValidatorBuilder, OpAddOnsBuilder, OpEngineApiBuilder, OpNode,
};
use tokio::sync::oneshot;

#[tokio::main]
async fn main() {
    // Op node configuration and setup
    let config = NodeConfig::new(BASE_MAINNET.clone());
    let db = create_test_rw_db();
    let args = RollupArgs::default();
    let op_node = OpNode::new(args);

    let (engine_api_tx, _engine_api_rx) = oneshot::channel();

    let engine_api =
        EngineApiExt::new(OpEngineApiBuilder::<OpEngineValidatorBuilder>::default(), move |api| {
            let _ = engine_api_tx.send(api);
        });

    // Create the add-ons using the builder with explicit types
    // Build with default types, then replace the engine API
    let add_ons = OpAddOnsBuilder::<Optimism>::default()
        .build_without_hooks::<
            OpEngineValidatorBuilder,
            OpEngineApiBuilder<OpEngineValidatorBuilder>,
            BasicEngineValidatorBuilder<OpEngineValidatorBuilder>
        >()
        .with_engine_api(engine_api);

    let _builder = NodeBuilder::new(config)
        .with_database(db)
        .with_types::<OpNode>()
        .with_components(op_node.components())
        .with_add_ons(add_ons)
        .on_component_initialized(move |ctx| {
            let _provider = ctx.provider();
            Ok(())
        })
        .on_node_started(|_full_node| {
            // In the new pattern, RPC access happens through the node handle
            // after launch completes
            Ok(())
        })
        .check_launch();
}
