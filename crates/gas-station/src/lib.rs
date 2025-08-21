// a rough port of https://github.com/lightlink-network/ll-geth/blob/5fc91fa5288a54b3761f43126655fc5e30923ab7/core/gas_station.go
// CalculateGasStationStorageSlots -> calculate_slots
// ValidateGaslessTx -> validate_gasless_tx

use alloy_primitives::{address, b256, keccak256, Address, B256, Bytes, Log, U256};
use reth_storage_api::{errors::ProviderResult, StateProvider, StateWriter};
use revm_database::states::{PlainStorageChangeset, StateChangeset};

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
        Self { enabled: true, address: GAS_STATION_PREDEPLOY }
    }
}

/// Result of keccak256(abi.encode(uint256(keccak256("gasstation.main")) - 1)) & ~bytes32(uint256(0xff));
pub const GAS_STATION_STORAGE_LOCATION: B256 =
    b256!("0x64d1d9a8a451551a9514a2c08ad4e1552ed316d7dd2778a4b9494de741d8e000");

/// Storage slots used by the GasStation contract for a given `to` (recipient)
/// and optional `from`.
#[derive(Clone, Debug)]
pub struct GasStationStorageSlots {
    pub registered_slot: B256,  // struct base slot (has registered/active packed)
    pub active_slot: B256,  // TODO REMOVE THIS
    pub credits_slot: B256,     // credits slot
    pub nested_whitelist_map_base_slot: B256,  // base slot for the nested whitelist mapping
    pub whitelist_enabled_slot: B256,  // whitelist enabled flag
    pub single_use_enabled_slot: B256,  // single use enabled flag  
    pub used_addresses_map_base_slot: B256,  // base slot for the nested usedAddresses mapping
}

/// calculates the storage slot hashes for a specific registered contract within the GasStation's `contracts` mapping.
/// it returns the base slot for the struct (holding packed fields), the slot for credits,
/// the slot for whitelistEnabled, and the base slot for the nested whitelist mapping.
pub fn calculate_gas_station_slots(registered_contract_address: Address) -> GasStationStorageSlots {
	// The 'contracts' mapping is at offset 1 from the storage location
	// (dao is at offset 0, contracts is at offset 1)
    let contracts_map_slot = U256::from_be_bytes(GAS_STATION_STORAGE_LOCATION.0) + U256::from(1);

    // Calculate the base slot for the struct entry in the mapping
    // - left pad the address to 32 bytes
    let mut key_padded = [0u8; 32];
    key_padded[12..].copy_from_slice(registered_contract_address.as_slice()); // Left-pad 20-byte address to 32 bytes
    // - I expect this is left padded because big endian etc
    let map_slot_padded = contracts_map_slot.to_be_bytes::<32>();
    // - keccak256(append(keyPadded, mapSlotPadded...))
    let combined = [key_padded, map_slot_padded].concat();
    let struct_base_slot_hash = keccak256(combined);

	// Calculate subsequent slots by adding offsets to the base slot hash
	// New struct layout: bool registered, bool active, address admin (all packed in slot 0)
	// uint256 credits (slot 1), bool whitelistEnabled (slot 2), mapping whitelist (slot 3)
	// bool singleUseEnabled (slot 4), mapping usedAddresses (slot 5)
    let struct_base_slot_u256 = U256::from_be_bytes(struct_base_slot_hash.0);

    // Slot for 'credits' (offset 1 from base - after the packed bools and address)
    let credits_slot_u256 = struct_base_slot_u256 + U256::from(1);
    let credit_slot_hash = B256::from_slice(&credits_slot_u256.to_be_bytes::<32>());

    // Slot for 'whitelistEnabled' (offset 2 from base)
    let whitelist_enabled_slot_u256 = struct_base_slot_u256 + U256::from(2);
    let whitelist_enabled_slot_hash = B256::from_slice(&whitelist_enabled_slot_u256.to_be_bytes::<32>());

    // Base slot for the nested 'whitelist' mapping (offset 3 from base)
    let nested_whitelist_map_base_slot_u256 = struct_base_slot_u256 + U256::from(3);
    let nested_whitelist_map_base_slot_hash = B256::from_slice(&nested_whitelist_map_base_slot_u256.to_be_bytes::<32>());

    // Slot for 'singleUseEnabled' (offset 4 from base)
    let single_use_enabled_slot_u256 = struct_base_slot_u256 + U256::from(4);
    let single_use_enabled_slot_hash = B256::from_slice(&single_use_enabled_slot_u256.to_be_bytes::<32>());

    // Base slot for the nested 'usedAddresses' mapping (offset 5 from base)
    let used_addresses_map_base_slot_u256 = struct_base_slot_u256 + U256::from(5);
    let used_addresses_map_base_slot_hash = B256::from_slice(&used_addresses_map_base_slot_u256.to_be_bytes::<32>());

    GasStationStorageSlots {
        registered_slot: struct_base_slot_hash,
        active_slot: struct_base_slot_hash,  
        credits_slot: credit_slot_hash,
        whitelist_enabled_slot: whitelist_enabled_slot_hash,
        single_use_enabled_slot: single_use_enabled_slot_hash,
        nested_whitelist_map_base_slot: nested_whitelist_map_base_slot_hash,
        used_addresses_map_base_slot: used_addresses_map_base_slot_hash,
    }
}

/// Computes the storage slot hash for a nested mapping
pub fn calculate_nested_mapping_slot(key: Address, base_slot: B256) -> B256 {
    // Left-pad the address to 32 bytes
    let mut key_padded = [0u8; 32];
    key_padded[12..].copy_from_slice(key.as_slice()); // Left-pad 20-byte address to 32 bytes
    
    // The base_slot is already 32 bytes (B256)
    let map_base_slot_padded = base_slot.0;
    
    // Combine: key first, then base slot
    let combined = [key_padded, map_base_slot_padded].concat();
    keccak256(combined)
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
    let slots = calculate_gas_station_slots(to);

    // 2. read a storage slot
    // - helper to read a storage slot at gas station address
    let read_slot =
        |slot: B256| -> Option<U256> { state.storage(cfg.address, slot.into()).ok().flatten() };

    //  -> read GaslessContract.registered
    let registered_slot = read_slot(slots.registered_slot);
    let registered = registered_slot.unwrap_or_default() != U256::ZERO;
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
        let whitelist_slot = calculate_nested_mapping_slot(from, slots.nested_whitelist_map_base_slot);
        let whitelist_status = read_slot(whitelist_slot).unwrap_or_default() != U256::ZERO;
        if !whitelist_status {
            return Err(GaslessValidationError::NotWhitelisted);
        }
    }

    // 7. check for single-use
    let single_use_enabled =
        read_slot(slots.single_use_enabled_slot).unwrap_or_default() != U256::ZERO;
    if single_use_enabled {
        let used_addresses_slot = calculate_nested_mapping_slot(from, slots.used_addresses_map_base_slot);
        let used_addresses_status = read_slot(used_addresses_slot).unwrap_or_default() != U256::ZERO;
        if used_addresses_status {
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

/// Represents the storage/log effects that should be applied after a successful gasless tx.
#[derive(Clone, Debug, Default)]
pub struct GaslessPostExecEffects {
    /// Keyed by storage slot hash. Values are raw U256 slot values to write.
    pub storage_writes: Vec<(B256, U256)>,
    /// Optional log to emit: `CreditsUsed(address,address,uint256,uint256)`.
    pub log: Option<Log>,
}

/// Computes the post-execution effects for a gasless transaction:
/// - Deducts `gas_used` from the contract's credits (saturating at 0)
/// - If single-use is enabled, marks `from` as used in `usedAddresses` mapping
/// Returns a struct with the storage writes and the log to emit.
/// 
/// NOTE: DOESNT ACTUALLY APPLY CHANGES!!!!
/// see `apply_gasless_post_exec`...
pub fn compute_gasless_post_exec_effects<SP: StateProvider>(
    cfg: &GasStationConfig,
    to: Address,
    from: Address,
    gas_used: u64,
    state: &SP,
) -> GaslessPostExecEffects {
    // If feature is disabled or address not configured, produce no-op effects.
    if !cfg.enabled || cfg.address.is_zero() {
        return GaslessPostExecEffects::default();
    }

    // - helper to read a storage slot at gas station address
    let read_slot =
        |slot: B256| -> Option<U256> { state.storage(cfg.address, slot.into()).ok().flatten() };

    let slots = calculate_gas_station_slots(to);

    // Calculate new credits
    let available_credits = read_slot(slots.credits_slot);
    let gas_used_u256 = U256::from(gas_used);
    let new_credits = available_credits.unwrap_or_default().saturating_sub(gas_used_u256); // saturating means if it goes below 0, it stays at 0, no underflow
    
    // Prepare storage writes
    let mut storage_writes = Vec::with_capacity(2);
    storage_writes.push((slots.credits_slot, new_credits));
    
    // - if single use mark it as used
    let single_use_enabled = read_slot(slots.single_use_enabled_slot).unwrap_or_default() != U256::ZERO;
    if single_use_enabled {
        let used_addresses_slot = calculate_nested_mapping_slot(from, slots.used_addresses_map_base_slot);
        storage_writes.push((used_addresses_slot, U256::from(1u64)));
    }

    // calculate log data
    // event CreditsUsed(
    //     address indexed contractAddress, address indexed caller, uint256 gasUsed, uint256 creditsDeducted
    // );
    // topics: [signature, indexed contractAddress, indexed caller]
    let topic0 = credits_used_topic0();
    let to_bytes = to.into_word();
    let from_bytes = from.into_word();
    let topics = vec![topic0, to_bytes, from_bytes];
    let data = encode_credits_used_log_data(gas_used_u256, gas_used_u256);

    let log = Log::new_unchecked(
        cfg.address,
        topics,
        Bytes::copy_from_slice(&data),
    );

    GaslessPostExecEffects { storage_writes, log: Some(log) }
}


/// Applies the post-execution effects to the provided writer and returns the prepared log.
///
/// This is a convenience helper: callers that can directly write to EVM state can implement
/// `StorageWriter` and invoke this to update credits/mark single-use, then attach the returned
/// log to the transaction receipt.
pub fn apply_gasless_post_exec<W: StateWriter>(
    writer: &mut W,
    cfg: &GasStationConfig,
    effects: GaslessPostExecEffects,
) -> ProviderResult<()> {
    // If no effects, just return early
    if effects.storage_writes.is_empty() {
        return Ok(());
    }


    // Convert storage writes to the format expected by PlainStorageChangeset
    let storage: Vec<(U256, U256)> = effects.storage_writes
        .into_iter()
        .map(|(slot, value)| (U256::from_be_bytes(slot.0), value))
        .collect();

    // Create a single PlainStorageChangeset for the gas station address
    let storage_changeset = PlainStorageChangeset {
        address: cfg.address,
        wipe_storage: false,
        storage,
    };

    let changes = StateChangeset {
        accounts: Default::default(),
        storage: vec![storage_changeset],
        contracts: Default::default(),
    };

    // Write the changes
    writer.write_state_changes(changes)
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
}
