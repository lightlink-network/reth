use revm_primitives::U256;

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum GaslessValidationError {
    #[error("gas station feature disabled")]
    Disabled,
    #[error("destination is create transaction")]
    Create,
    #[error("gas station contract not configured")]
    NoAddress,
    #[error("not registered for gasless")]
    NotRegistered,
    #[error("contract inactive for gasless")]
    Inactive,
    #[error("insufficient credits: have {available}, need {needed}")]
    InsufficientCredits { available: U256, needed: U256 },
    #[error("whitelist required")]
    NotWhitelisted,
    #[error("single-use already used")]
    SingleUseConsumed,
}