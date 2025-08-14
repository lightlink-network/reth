// a rough port of https://github.com/lightlink-network/ll-geth/blob/5fc91fa5288a54b3761f43126655fc5e30923ab7/core/gas_station.go
// CalculateGasStationStorageSlots -> calculate_slots
// ValidateGaslessTx -> validate_gasless_tx

use alloy_primitives::{address, b256, keccak256, Address, B256, U256};
use reth_storage_api::StateProvider;

#[derive(Clone, Debug)] // lets us clone (.clone()) and print debug info ("{:?}")
pub struct GasStationConfig {
    pub enabled: bool,
    pub address: Address,
}

// pub const CREDITS_USED_TOPIC0: B256 = keccak256(b"CreditsUsed(address,address,uint256,uint256)");

/// Topic0 for CreditsUsed event.
pub fn credits_used_topic0() -> B256 {
    // GUESS WE CAN PRECOMPUTE THIS AND HAVE IT A CONSTANT
    keccak256(b"CreditsUsed(address,address,uint256,uint256)")
}

/// predeploy local for GasStation by default
pub const GAS_STATION_PREDEPLOY: Address = address!("0x4300000000000000000000000000000000000001");

impl Default for GasStationConfig {
    fn default() -> Self {
        // Set it as disabled by default
        // TODO: make it enabled by default?? idk.
        Self { enabled: false, address: GAS_STATION_PREDEPLOY }
    }
}

/// Result of keccak256(abi.encode(uint256(keccak256("gasstation.main")) - 1)) & ~bytes32(uint256(0xff));
pub const GAS_STATION_STORAGE_LOCATION: B256 =
    b256!("0x64d1d9a8a451551a9514a2c08ad4e1552ed316d7dd2778a4b9494de741d8e000");

/// Storage slots used by the GasStation contract for a given `to` (recipient)
/// and optional `from`.
#[derive(Clone, Debug)]
pub struct GasStationStorageSlots {
    pub contracts_slot: B256,
    pub contract_slot: B256,
    pub registered_slot: B256,
    pub active_slot: B256,
    pub admin_slot: B256,
    pub credits_slot: B256,
    pub whitelist_enabled_slot: B256,
    pub single_use_enabled_slot: B256,
    pub whitelist_user_slot: Option<B256>,
    pub used_addresses_user_slot: Option<B256>,
}

/// computes storage slots according to solidity layout for
/// mapping(address => GaslessContract) contracts
/// and fields of GaslessContract etc
pub fn calculate_slots(
    gas_station_storage_location: B256,
    to: Address,
    from: Option<Address>,
) -> GasStationStorageSlots {
    // GasStationStorage Layout:
    // 0: dao
    // 1: contracts (mapping) -> mapping slot index 1 within the struct
    // 2: creditPackages (mapping)
    // 3: nextPackageId (u256)
    // We need base slot for `contracts` to compute keccak(key . slot).

    // contracts mapping position within the struct
    let contracts_field_index = U256::from(1u64);

    // Step 1.derive the slot representing `contracts`.
    let mut buf = [0u8; 64];
    // – keccak256(abi.encode(field_index, storage_location))
    buf[..32].copy_from_slice(B256::from(contracts_field_index).as_slice()); // add field_index to buf
    buf[32..].copy_from_slice(gas_station_storage_location.as_slice()); // add storage_location to buf
    let contracts_slot = keccak256(buf); // hash it

    // Step 2. derive the slot for key `to` in the `contracts` mapping.
    let mut elem_buf = [0u8; 64];
    // left-pad address to 32 bytes
    elem_buf[12..32].copy_from_slice(to.as_slice());
    elem_buf[32..].copy_from_slice(contracts_slot.as_slice());
    let contract_slot = keccak256(elem_buf);

    // fields of GaslessContract layout (packed sequentially starting at contract_slot):
    // 0: bool registered
    // 1: bool active
    // 2: address admin
    // 3: uint256 credits
    // 4: bool whitelistEnabled
    // 5: mapping(address => bool) whitelist (slot index 5)
    // 6: bool singleUseEnabled
    // 7: mapping(address => bool) usedAddresses (slot index 7)
    // Note: Booleans may be bit-packed but solidity puts each bool in its own slot when followed by mappings.

    // Step 3. derive the slots for the fields of GaslessContract.
    let registered_slot = contract_slot;
    let active_slot = add_u64_to_b256(contract_slot, 1);
    let admin_slot = add_u64_to_b256(contract_slot, 2);
    let credits_slot = add_u64_to_b256(contract_slot, 3);
    let whitelist_enabled_slot = add_u64_to_b256(contract_slot, 4);
    let whitelist_mapping_slot = add_u64_to_b256(contract_slot, 5);
    let single_use_enabled_slot = add_u64_to_b256(contract_slot, 6);
    let used_addresses_mapping_slot = add_u64_to_b256(contract_slot, 7);

    // Step 4. If `from` provided, compute nested mapping keys
    let whitelist_user_slot = from.map(|addr| {
        let mut buf = [0u8; 64];
        buf[12..32].copy_from_slice(addr.as_slice());
        buf[32..].copy_from_slice(whitelist_mapping_slot.as_slice());
        keccak256(buf)
    });
    let used_addresses_user_slot = from.map(|addr| {
        let mut buf = [0u8; 64];
        buf[12..32].copy_from_slice(addr.as_slice());
        buf[32..].copy_from_slice(used_addresses_mapping_slot.as_slice());
        keccak256(buf)
    });

    // Step 5. return the slots
    GasStationStorageSlots {
        contracts_slot,
        contract_slot,
        registered_slot,
        active_slot,
        admin_slot,
        credits_slot,
        whitelist_enabled_slot,
        single_use_enabled_slot,
        whitelist_user_slot,
        used_addresses_user_slot,
    }
}

#[derive(Clone, Debug)]
pub struct GaslessValidation {
    pub available_credits: U256,
    pub required_credits: U256,
    pub slots: GasStationStorageSlots,
}

#[derive(thiserror::Error, Clone, Debug)]
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

/// A provider of pending credit usage, ... used by the txpool.
pub trait PendingCreditUsageProvider {
    fn pending_credits_for_destination(&self, destination: &Address) -> U256;
}

/// In-memory pending credit usage map keyed by destination address.
#[derive(Default, Debug)]
pub struct PendingCreditUsageMap {
    inner: std::collections::HashMap<Address, U256>,
}

impl PendingCreditUsageMap {
    pub fn new() -> Self {
        Self { inner: Default::default() }
    }
    pub fn add_usage(&mut self, destination: Address, amount: U256) {
        let entry = self.inner.entry(destination).or_insert(U256::ZERO);
        *entry = *entry + amount;
    }
    pub fn remove_usage(&mut self, destination: Address, amount: U256) {
        let entry = self.inner.entry(destination).or_insert(U256::ZERO);
        *entry = entry.saturating_sub(amount);
    }
}

impl PendingCreditUsageProvider for PendingCreditUsageMap {
    fn pending_credits_for_destination(&self, destination: &Address) -> U256 {
        self.inner.get(destination).copied().unwrap_or(U256::ZERO)
    }
}

/// Validates a gasless transaction against on-chain gas station storage and pending usage.
pub fn validate_gasless_tx<SP: StateProvider>(
    cfg: &GasStationConfig,
    state: &SP,
    gas_station_storage_location: B256,
    to: Address,
    from: Address,
    gas_limit: u64,
    pending_provider: Option<&dyn PendingCreditUsageProvider>,
) -> Result<GaslessValidation, GaslessValidationError> {
    if !cfg.enabled {
        return Err(GaslessValidationError::Disabled);
    }
    if cfg.address.is_zero() {
        return Err(GaslessValidationError::NoAddress);
    }

    // 1. compute slots
    let slots = calculate_slots(gas_station_storage_location, to, Some(from));

    // 2. read a storage slot
    // - helper to read a storage slot at gas station address
    let read_slot =
        |slot: B256| -> Option<U256> { state.storage(cfg.address, slot.into()).ok().flatten() };

    //  -> read GaslessContract.registered
    let registered = read_slot(slots.registered_slot).unwrap_or_default() != U256::ZERO;
    if !registered {
        return Err(GaslessValidationError::NotRegistered);
    }

    //  -> read GaslessContract.active
    let active = read_slot(slots.active_slot).unwrap_or_default() != U256::ZERO;
    if !active {
        return Err(GaslessValidationError::Inactive);
    }

    // 3. read credits
    let available_credits = read_slot(slots.credits_slot).unwrap_or_default();

    // 4. calculate required credits
    let mut required = U256::from(gas_limit);
    // Include pool pending usage if provided
    if let Some(p) = pending_provider {
        required = required + p.pending_credits_for_destination(&to);
    }

    // 5. check if we have enough credits
    if available_credits < required {
        return Err(GaslessValidationError::InsufficientCredits {
            available: available_credits,
            needed: required,
        });
    }

    // 6. check whitelist
    let whitelist_enabled =
        read_slot(slots.whitelist_enabled_slot).unwrap_or_default() != U256::ZERO;
    if whitelist_enabled {
        // basically read whitelist[from] and check if it's true
        let ok = slots
            .whitelist_user_slot
            .and_then(|s| read_slot(s))
            .map(|v| v != U256::ZERO)
            .unwrap_or(false);
        if !ok {
            return Err(GaslessValidationError::NotWhitelisted);
        }
    }

    // 7. check for single-use
    let single_use_enabled =
        read_slot(slots.single_use_enabled_slot).unwrap_or_default() != U256::ZERO;
    if single_use_enabled {
        let used = slots
            .used_addresses_user_slot
            .and_then(|s| read_slot(s))
            .map(|v| v != U256::ZERO)
            .unwrap_or(false);
        if used {
            return Err(GaslessValidationError::SingleUseConsumed);
        }
    }

    Ok(GaslessValidation { available_credits, required_credits: required, slots })
}

/// encodes the CreditsUsed event log data payload (topics are computed by caller).
/// event CreditsUsed(address indexed contractAddress, address indexed caller, uint256 gasUsed, uint256 creditsDeducted)
pub fn encode_credits_used_log_data(gas_used: U256, credits_deducted: U256) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(B256::from(gas_used).as_slice());
    out[32..].copy_from_slice(B256::from(credits_deducted).as_slice());
    out
}

/// Add a small u64 delta to a B256 interpreted as a big endian integer.
/// TODO: VERIFY THIS IS CORRECT.
/// In future we should use https://crates.io/crates/num ???
fn add_u64_to_b256(value: B256, delta: u64) -> B256 {
    if delta == 0 {
        return value;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(value.as_slice());
    // add delta in big endian
    let mut i = 31usize;
    let mut carry = delta as u128; // up to 64 bits fits into u128
    while carry > 0 && i < 32 {
        let sum = bytes[i] as u128 + (carry & 0xFF);
        bytes[i] = (sum & 0xFF) as u8;
        carry = (carry >> 8) + (sum >> 8);
        if i == 0 {
            break;
        }
        i -= 1;
    }
    B256::from(bytes)
}

// ???
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic0_signature_hash() {
        let t = credits_used_topic0();
        assert_eq!(t, keccak256(b"CreditsUsed(address,address,uint256,uint256)"));
    }

    #[test]
    fn add_delta_to_b256() {
        let base = B256::ZERO;
        assert_eq!(add_u64_to_b256(base, 0), base);
        assert_eq!(
            add_u64_to_b256(base, 1),
            B256::from_slice(&[0u8; 31].iter().cloned().chain([1u8]).collect::<Vec<_>>())
        );
        let max_low =
            B256::from_slice(&[0u8; 24].iter().cloned().chain([0xFFu8; 8]).collect::<Vec<_>>());
        let res = add_u64_to_b256(max_low, 1);
        // expect carry into next byte
        let mut expect = [0u8; 32];
        expect[23] = 1;
        assert_eq!(res, B256::from(expect));
    }
}
