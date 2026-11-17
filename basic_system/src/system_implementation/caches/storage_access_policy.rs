use zk_ee::execution_environment_type::ExecutionEnvironmentType;

use zk_ee::system::{errors::system::SystemError, Resources};

/// EE-specific IO charging.
pub trait StorageAccessPolicy<R: Resources, V>: 'static + Sized {
    /// Charge for a warm read (already in cache).
    fn charge_warm_storage_read(
        &self,
        ee_type: ExecutionEnvironmentType,
        resources: &mut R,
    ) -> Result<(), SystemError>;

    /// SYSCOIN: Charge only the EE part of a cold storage read. Keeping this
    /// separate from the native part lets bootloader fee-ledger IO account for
    /// prover work without changing EIP-2929 warmth.
    fn charge_cold_storage_read_ergs_extra(
        &self,
        ee_type: ExecutionEnvironmentType,
        resources: &mut R,
    ) -> Result<(), SystemError>;

    /// SYSCOIN: Charge only the native part of a cold storage read.
    fn charge_cold_storage_read_native_extra(
        &self,
        resources: &mut R,
        is_new_slot: bool,
    ) -> Result<(), SystemError>;

    /// SYSCOIN: Charge the complete cold-read extra. Account-cache callers still need
    /// the combined operation, while slot storage tracks EE warmth and native
    /// admission independently.
    fn charge_cold_storage_read_extra(
        &self,
        ee_type: ExecutionEnvironmentType,
        resources: &mut R,
        is_new_slot: bool,
    ) -> Result<(), SystemError>;

    /// Charge the additional cost of performing a write.
    /// This cost is added to the cost of reading.
    /// We assume writing is always at least as expensive
    /// as reading.
    ///
    /// `is_warm_access`: EIP-2929 access warmness (any prior access in this tx).
    /// `is_cold_write_charged`: whether cold write extra (native merkle paths)
    ///   was already charged for this slot in this tx.
    fn charge_storage_write_extra(
        &self,
        ee_type: ExecutionEnvironmentType,
        initial_value: &V,
        current_value: &V,
        new_value: &V,
        resources: &mut R,
        is_warm_access: bool,
        is_cold_write_charged: bool,
        is_new_slot: bool,
    ) -> Result<(), SystemError>;

    /// Refund some resources if needed
    fn refund_for_storage_write(
        &self,
        ee_type: ExecutionEnvironmentType,
        value_at_tx_start: &V,
        current_value: &V,
        new_value: &V,
        resources: &mut R,
        refund_counter: &mut R,
    ) -> Result<(), SystemError>;
}
