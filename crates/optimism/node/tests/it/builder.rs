//! Node builder setup tests.

use reth_db::test_utils::create_test_rw_db;
use reth_node_api::{FullNodeComponents, FullNodeTypesAdapter};
use reth_node_builder::{Node, NodeBuilder, NodeConfig};
use reth_optimism_chainspec::BASE_MAINNET;
use reth_optimism_node::{args::RollupArgs, OpNode};
use reth_provider::providers::BlockchainProvider;

#[test]
fn test_basic_setup() {
    // parse CLI -> config
    let config = NodeConfig::new(BASE_MAINNET.clone());
    let db = create_test_rw_db();
    let args = RollupArgs::default();
    let op_node = OpNode::new(args);
    type N = FullNodeTypesAdapter<
        OpNode,
        std::sync::Arc<reth_db::test_utils::TempDatabase<reth_db::DatabaseEnv>>,
        BlockchainProvider<
            reth_node_api::NodeTypesWithDBAdapter<
                OpNode,
                std::sync::Arc<reth_db::test_utils::TempDatabase<reth_db::DatabaseEnv>>,
            >,
        >,
    >;
    let _builder = NodeBuilder::new(config)
        .with_database(db)
        .with_types_and_provider::<OpNode, BlockchainProvider<_>>()
        .with_components(<OpNode as Node<N>>::components_builder(&op_node))
        .with_add_ons(<OpNode as Node<N>>::add_ons(&op_node))
        .on_component_initialized(move |ctx| {
            let _provider = ctx.provider();
            Ok(())
        })
        .on_node_started(|_full_node| Ok(()))
        .on_rpc_started(|_ctx, handles| {
            let _client = handles.rpc.http_client();
            Ok(())
        })
        .extend_rpc_modules(|ctx| {
            let _ = ctx.config();
            let _ = ctx.node().provider();

            Ok(())
        })
        .check_launch();
}
