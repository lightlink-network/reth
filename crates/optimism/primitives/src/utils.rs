//! Optimism utility functions

/// Returns true if the transaction is a zero-fee transaction.
///
/// Rules:
/// - Legacy/EIP-2930: gas_price == 0
/// - EIP-1559/EIP-4844/EIP-7702: max_fee_per_gas == 0
pub fn is_gasless<T: alloy_consensus::Transaction + alloy_eips::eip2718::Typed2718>(tx: &T) -> bool {
    match tx.ty() {
        0 | 1 => tx.gas_price().unwrap_or(0) == 0, // Legacy/EIP-2930
        2 | 3 | 4 => tx.max_fee_per_gas() == 0, // EIP-1559/EIP-4844/EIP-7702
        _ => false,
    }
}
