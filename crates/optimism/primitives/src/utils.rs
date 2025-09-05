//! Optimism utility functions

/// Returns true if the transaction is a zero-fee transaction.
///
/// Rules:
/// - Legacy
/// - EIP-1559
pub fn is_gasless<T: alloy_consensus::Transaction + alloy_eips::eip2718::Typed2718>(tx: &T) -> bool {
    match tx.ty() {
        1 => tx.gas_price().unwrap_or(0) == 0,
        2 => {
            tx.max_fee_per_gas() == 0 && tx.max_priority_fee_per_gas().unwrap_or_default() == 0
        }
        _ => false,
    }
}
