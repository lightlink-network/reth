use revm_primitives::U256;

/// Errors that can occur during gasless transaction validation.
///
/// These errors represent various failure modes when validating whether a transaction
/// is eligible for gasless execution through the gas station mechanism.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum GaslessValidationError {
    /// The gas station feature is disabled in the current configuration.
    #[error("gas station feature disabled")]
    Disabled,
    /// The transaction is a contract creation transaction, which is not supported for gasless execution.
    #[error("destination is create transaction")]
    Create,
    /// No gas station contract address has been configured.
    #[error("gas station contract not configured")]
    NoAddress,
    /// The destination contract is not registered for gasless transactions.
    #[error("not registered for gasless")]
    NotRegistered,
    /// The destination contract is registered but currently inactive for gasless transactions.
    #[error("contract inactive for gasless")]
    Inactive,
    /// Insufficient credits available for the gasless transaction.
    #[error("insufficient credits: have {available}, need {needed}")]
    InsufficientCredits {
        /// The amount of credits currently available.
        available: U256,
        /// The amount of credits needed for this transaction.
        needed: U256,
    },
    /// The transaction sender is not on the required whitelist.
    #[error("whitelist required")]
    NotWhitelisted,
    /// A single-use gasless transaction has already been consumed.
    #[error("single-use already used")]
    SingleUseConsumed,
}
