//! Node add-ons. Depend on core [`NodeComponents`](crate::NodeComponents).

use reth_node_api::{FullNodeComponents, NodeAddOns};
use reth_rpc::eth::EthApiTypes;

use crate::{
    exex::BoxedLaunchExEx,
    hooks::NodeHooks,
    rpc::{RethRpcServerHandles, RpcContext, RpcHooks},
};

/// Additional node extensions.
///
/// At this point we consider all necessary components defined.
pub struct AddOns<Node: FullNodeComponents, AddOns: NodeAddOns<Node>, RpcHooks = ()> {
    /// Additional `NodeHooks` that are called at specific points in the node's launch lifecycle.
    pub hooks: NodeHooks<Node, AddOns>,
    /// RPC hooks that will be passed to the RPC addons at launch time.
    /// These are stored here temporarily during the migration from storing them in `RpcAddOns`.
    pub rpc_hooks: RpcHooks,
    /// The `ExExs` (execution extensions) of the node.
    pub exexs: Vec<(String, Box<dyn BoxedLaunchExEx<Node>>)>,
    /// Additional captured addons.
    pub add_ons: AddOns,
}

/// Trait for `AddOns` that have typed RPC hooks.
///
/// This trait is used during the migration to allow storing RPC hooks
/// directly in the `AddOns` struct instead of in `RpcAddOns`.
pub trait AddOnsWithRpcHooks {
    /// The node type
    type Node: FullNodeComponents;
    /// The addon type
    type AddOns: NodeAddOns<Self::Node>;
    /// The `EthApi` type
    type EthApi: EthApiTypes;

    /// Sets the `on_rpc_started` hook
    fn set_on_rpc_started_hook<F>(&mut self, hook: F)
    where
        F: FnOnce(
                RpcContext<'_, Self::Node, Self::EthApi>,
                RethRpcServerHandles,
            ) -> eyre::Result<()>
            + Send
            + 'static;

    /// Sets the `extend_rpc_modules` hook
    fn set_extend_rpc_modules_hook<F>(&mut self, hook: F)
    where
        F: FnOnce(RpcContext<'_, Self::Node, Self::EthApi>) -> eyre::Result<()> + Send + 'static;
}

impl<Node, AO, EthApi> AddOnsWithRpcHooks for AddOns<Node, AO, RpcHooks<Node, EthApi>>
where
    Node: FullNodeComponents,
    AO: NodeAddOns<Node>,
    EthApi: EthApiTypes,
{
    type Node = Node;
    type AddOns = AO;
    type EthApi = EthApi;

    fn set_on_rpc_started_hook<F>(&mut self, hook: F)
    where
        F: FnOnce(
                RpcContext<'_, Self::Node, Self::EthApi>,
                RethRpcServerHandles,
            ) -> eyre::Result<()>
            + Send
            + 'static,
    {
        self.rpc_hooks.set_on_rpc_started(hook);
    }

    fn set_extend_rpc_modules_hook<F>(&mut self, hook: F)
    where
        F: FnOnce(RpcContext<'_, Self::Node, Self::EthApi>) -> eyre::Result<()> + Send + 'static,
    {
        self.rpc_hooks.set_extend_rpc_modules(hook);
    }
}
