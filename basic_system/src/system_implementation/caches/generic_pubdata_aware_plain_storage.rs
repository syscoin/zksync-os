//! Storage cache, backed by a history map.
use crate::system_implementation::caches::cache_element_properties::CacheElementProperties;
use crate::system_implementation::caches::storage_access_policy::StorageAccessPolicy;
use alloc::fmt::Debug;
use core::alloc::Allocator;
use ruint::aliases::B160;
use zk_ee::common_structs::cache_record::CacheRecord;
use zk_ee::common_structs::history_counter::HistoryCounter;
use zk_ee::common_structs::history_counter::HistoryCounterSnapshotId;
use zk_ee::common_structs::history_counter::NonEmptyHistoryCounter;
use zk_ee::common_traits::key_like_with_bounds::{KeyLikeWithBounds, TyEq};
use zk_ee::execution_environment_type::ExecutionEnvironmentType;
use zk_ee::internal_error;
use zk_ee::oracle::basic_queries::InitialStorageSlotQuery;
use zk_ee::oracle::IOOracle;
use zk_ee::system::errors::internal::InternalError;
use zk_ee::{
    memory::stack_trait::StackFactory,
    oracle::simple_oracle_query::SimpleOracleQuery,
    storage_types::StorageAddress,
    system::{errors::system::SystemError, Resources},
    types_config::{EthereumIOTypesConfig, SystemIOTypesConfig},
};

use zk_ee::common_structs::history_map::*;

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TransactionId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsWarmRead(pub bool);

type AddressItem<'a, K, V, A> =
    HistoryMapItemRefMut<'a, K, CacheRecord<V, StorageElementMetadata>, A, CacheElementProperties>;

#[derive(Default, Clone)]
pub struct StorageElementMetadata {
    /// Transaction where this slot was last accessed (read or write).
    /// Considered warm if equal to Some(current_tx).
    pub last_touched_in_tx: Option<TransactionId>,
    /// SYSCOIN: Transaction where native cold-read Merkle work was paid. This
    /// is deliberately independent from EIP-2929 warmth: bootloader fee-ledger
    /// IO pays prover work without warming user-visible storage. `None` is a
    /// non-colliding sentinel even for block-level transaction ID 0.
    pub native_read_extra_charged_in_tx: Option<TransactionId>,
    /// Transaction where cold write extra was last charged for this slot.
    /// Used to distinguish "warm because previously written" (write paths paid)
    /// from "warm because previously read" (only read paths paid).
    pub write_extra_charged_in_tx: Option<TransactionId>,
    /// Whether the cold NEW-slot read extra was already charged for this slot.
    /// Kept in rollback-aware metadata rather than derived from cache presence:
    /// entries materialized by a transaction that is later dropped from the
    /// block stay in the cache, but their metadata updates are rolled back
    /// together with the charge, so charging never depends on dropped
    /// transactions (which the proving run doesn't re-execute).
    pub new_read_extra_charged: bool,
}

impl StorageElementMetadata {
    pub fn considered_warm(&self, current_tx_id: TransactionId) -> bool {
        self.last_touched_in_tx == Some(current_tx_id)
    }

    // SYSCOIN: Native read admission is independent from EVM warmth.
    fn native_read_extra_charged(&self, current_tx_id: TransactionId) -> bool {
        self.native_read_extra_charged_in_tx == Some(current_tx_id)
    }
}

// SYSCOIN: Fee-ledger IO preserves user-visible EVM access metadata while
// ordinary storage accesses retain upstream warming behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvmWarmthMode {
    Update,
    Preserve,
}

#[derive(Debug)]
pub struct StorageSnapshotId {
    pub cache: CacheSnapshotId,
    pub evm_refunds_counter: HistoryCounterSnapshotId,
    // SYSCOIN: Snapshot the single fee-precharge EVM-original override with
    // public storage and refunds.
    pub evm_original_override: HistoryCounterSnapshotId,
}

pub struct GenericPubdataAwarePlainStorage<
    K: KeyLikeWithBounds,
    V,
    A: Allocator + Clone, // = Global,
    SF: StackFactory<M>,
    const M: usize,
    R: Resources,
    P: StorageAccessPolicy<R, V>,
> {
    pub(crate) cache:
        HistoryMap<K, CacheRecord<V, StorageElementMetadata>, A, CacheElementProperties>,
    /// SYSCOIN: A transaction can precharge exactly one sender-credit slot, so
    /// its payload EVM-original override is a bounded, rollback-aware singleton.
    /// The counter stays empty for non-tank transactions. Its O(1) history
    /// update substitutes for the EVM refund-counter update deliberately
    /// skipped by the special write and is covered by the same
    /// warm-storage-write native allowance.
    pub(crate) evm_original_override: HistoryCounter<Option<(K, V)>, SF, M, A>,
    pub(crate) resources_policy: P,
    // Note: this doesn't need to be equal to the actual tx number in the block, it just needs to be able to differentiate between transactions.
    pub(crate) current_tx_id: TransactionId,
    pub(crate) evm_refunds_counter: NonEmptyHistoryCounter<R, SF, M, A>, // Used to keep track of EVM gas refunds
    pub(crate) alloc: A,
    pub(crate) _marker: core::marker::PhantomData<(R, SF)>,
}

impl<
        K: 'static + KeyLikeWithBounds,
        V: Default
            + Clone
            + Debug
            + PartialEq
            + From<<EthereumIOTypesConfig as SystemIOTypesConfig>::StorageValue>,
        A: Allocator + Clone,
        SF: StackFactory<M>,
        const M: usize,
        R: Resources,
        P: StorageAccessPolicy<R, V>,
    > GenericPubdataAwarePlainStorage<K, V, A, SF, M, R, P>
{
    pub fn new_from_parts(allocator: A, resources_policy: P) -> Self {
        Self {
            cache: HistoryMap::new(allocator.clone()),
            // SYSCOIN: Initialize the lazy per-transaction EVM-original singleton.
            evm_original_override: HistoryCounter::new(allocator.clone()),
            current_tx_id: TransactionId(0),
            resources_policy,
            evm_refunds_counter: NonEmptyHistoryCounter::new_with_initial(
                allocator.clone(),
                R::empty(),
            ),
            alloc: allocator.clone(),
            _marker: core::marker::PhantomData,
        }
    }

    pub fn begin_new_tx(&mut self) {
        self.cache.commit();
        // SYSCOIN: The next transaction has no fee-precharge override. The
        // previous transaction's public value was committed above.
        self.evm_original_override = HistoryCounter::new(self.alloc.clone());
        self.evm_refunds_counter =
            NonEmptyHistoryCounter::new_with_initial(self.alloc.clone(), R::empty());
        // Advance the warmth id at the start of each tx (not at finish) so that
        // block-level system operations, which run before the first `begin_new_tx`,
        // keep tx id 0 and are never considered warm by user transactions
        // (which start at id 1). Matches the account cache, which bumps on begin.
        self.current_tx_id.0 += 1;
    }

    pub fn finish_tx(&mut self) {}

    #[track_caller]
    pub fn start_frame(&mut self) -> StorageSnapshotId {
        StorageSnapshotId {
            cache: self.cache.snapshot(),
            evm_refunds_counter: self.evm_refunds_counter.snapshot(),
            // SYSCOIN: Capture the fee-precharge singleton in the same rollback frame.
            evm_original_override: self.evm_original_override.snapshot(),
        }
    }

    #[track_caller]
    #[must_use]
    pub fn finish_frame_impl(
        &mut self,
        rollback_handle: Option<&StorageSnapshotId>,
    ) -> Result<(), InternalError> {
        if let Some(x) = rollback_handle {
            self.evm_refunds_counter.rollback(x.evm_refunds_counter);
            // SYSCOIN: Roll back public value and EVM-original rebase together.
            self.evm_original_override.rollback(x.evm_original_override);
            self.cache.rollback(x.cache)
        } else {
            Ok(())
        }
    }

    /// Read element and initialize it if needed
    fn materialize_element<'a>(
        cache: &'a mut HistoryMap<
            K,
            CacheRecord<V, StorageElementMetadata>,
            A,
            CacheElementProperties,
        >,
        resources_policy: &mut P,
        current_tx_id: TransactionId,
        ee_type: ExecutionEnvironmentType,
        resources: &mut R,
        key: &'a K,
        oracle: &mut impl IOOracle,
        // SYSCOIN: Narrow fee-ledger callers preserve EVM warmth.
        evm_warmth_mode: EvmWarmthMode,
    ) -> Result<(AddressItem<'a, K, V, A>, IsWarmRead), SystemError>
    where
        StorageAddress<EthereumIOTypesConfig>: From<K>,
    {
        resources_policy.charge_warm_storage_read(ee_type, resources)?;

        // Conservative pre-gate for a cold read: the slot IO in the insertion
        // closure runs unmetered and the real cold charge only happens at warm-up,
        // so without this a tx could force that (prover) work and then fail the
        // charge, leaving it unpaid. So we check up front that the worst-case cold
        // read is affordable. Charging a throwaway copy of the resources here is
        // just a way to check we have enough — nothing is spent, the real charge
        // still happens at warm-up. A new slot is the costliest cold read (an extra
        // non-inclusion merkle path), so it upper-bounds the existing-slot case and
        // the real warm-up charge below cannot fail. The bound is data-independent
        // and warmth is rollback-aware, so the gate is identical across sequencer
        // and proving and never depends on cache-entry presence.
        // SYSCOIN: Gate the EVM and native cold components independently.
        let (is_evm_cold, is_native_cold) = match cache.get(key) {
            Some(item) => (
                !item.current().metadata().considered_warm(current_tx_id),
                !item
                    .current()
                    .metadata()
                    .native_read_extra_charged(current_tx_id),
            ),
            None => (true, true),
        };
        if (evm_warmth_mode == EvmWarmthMode::Update && is_evm_cold) || is_native_cold {
            let mut probe = resources.clone();
            if evm_warmth_mode == EvmWarmthMode::Update && is_evm_cold {
                resources_policy.charge_cold_storage_read_ergs_extra(ee_type, &mut probe)?;
            }
            if is_native_cold {
                resources_policy.charge_cold_storage_read_native_extra(&mut probe, true)?;
            }
        }

        cache
            .get_or_insert(key, || {
                // Element doesn't exist in cache yet, initialize it.
                // Cold access charging happens at warm-up below: the initial
                // record persists even if the inserting transaction is dropped
                // from the block, so anything charging-related must live in
                // rollback-aware metadata.
                let query_input = (*key).into();
                let data_from_oracle = InitialStorageSlotQuery::get(oracle, &query_input)
                    .map_err(|_| internal_error!("Must get initial slot value from oracle"))?;

                // We need to check that the initial value is default
                if data_from_oracle.is_new_storage_slot {
                    assert_eq!(
                        V::default(),
                        data_from_oracle.initial_value.into(),
                        "Initial value of empty slot must be trivial"
                    );
                }

                // Note: we initialize it as cold, should be warmed up separately
                // Since in case of revert it should become cold again and initial record can't be rolled back
                Ok((
                    CacheRecord::new(data_from_oracle.initial_value.into()),
                    CacheElementProperties::new(data_from_oracle.is_new_storage_slot, true),
                ))
            })
            .and_then(|mut x| {
                // SYSCOIN: EVM warmth and native cold admission are independent.
                let is_warm_read = x.current().metadata().considered_warm(current_tx_id);
                let native_read_extra_charged = x
                    .current()
                    .metadata()
                    .native_read_extra_charged(current_tx_id);
                let charge_as_new = !native_read_extra_charged
                    && x.element_properties().is_new_element()
                    && !x.current().metadata().new_read_extra_charged;
                let should_warm_evm = evm_warmth_mode == EvmWarmthMode::Update && !is_warm_read;
                if should_warm_evm {
                    resources_policy.charge_cold_storage_read_ergs_extra(ee_type, resources)?;
                }
                if !native_read_extra_charged {
                    // The NEW read extra (tree non-inclusion check) is charged once
                    // per slot per block; later cold accesses pay EXISTING. "Already
                    // paid" is tracked in metadata so that it rolls back together
                    // with the paying transaction if it's dropped from the block.
                    resources_policy
                        .charge_cold_storage_read_native_extra(resources, charge_as_new)?;
                }

                if should_warm_evm || !native_read_extra_charged {
                    x.update(|cache_record| {
                        cache_record.update_metadata(|m| {
                            if should_warm_evm {
                                m.last_touched_in_tx = Some(current_tx_id);
                            }
                            if !native_read_extra_charged {
                                m.native_read_extra_charged_in_tx = Some(current_tx_id);
                                if charge_as_new {
                                    m.new_read_extra_charged = true;
                                }
                            }
                            Ok(())
                        })
                    })?;
                }

                Ok((x, IsWarmRead(is_warm_read)))
            })
    }

    pub fn apply_read_impl(
        &mut self,
        ee_type: ExecutionEnvironmentType,
        key: &K,
        resources: &mut R,
        oracle: &mut impl IOOracle,
    ) -> Result<V, SystemError>
    where
        StorageAddress<EthereumIOTypesConfig>: From<K>,
    {
        // SYSCOIN: Ordinary reads retain upstream EVM warming behavior.
        let (addr_data, _) = Self::materialize_element(
            &mut self.cache,
            &mut self.resources_policy,
            self.current_tx_id,
            ee_type,
            resources,
            key,
            oracle,
            EvmWarmthMode::Update,
        )?;

        Ok(addr_data.current().value().clone())
    }

    pub fn apply_write_impl(
        &mut self,
        ee_type: ExecutionEnvironmentType,
        key: &K,
        new_value: &V,
        oracle: &mut impl IOOracle,
        resources: &mut R,
    ) -> Result<V, SystemError>
    where
        StorageAddress<EthereumIOTypesConfig>: From<K>,
    {
        // SYSCOIN: Ordinary writes retain upstream EVM warming behavior.
        let (mut addr_data, is_warm_read) = Self::materialize_element(
            &mut self.cache,
            &mut self.resources_policy,
            self.current_tx_id,
            ee_type,
            resources,
            key,
            oracle,
            EvmWarmthMode::Update,
        )?;

        // SYSCOIN: A bootloader fee precharge may rebase the one sender-credit
        // slot's EVM-original value while retaining its committed value for
        // pubdata, persistence, and outer rollback. The per-tx singleton keeps
        // ordinary SSTORE lookup fixed O(1); unrelated keys use committed state.
        let evm_original_override = self
            .evm_original_override
            .value()
            .and_then(Option::as_ref)
            .and_then(|(override_key, override_value)| {
                (override_key == key).then_some(override_value)
            });
        // SYSCOIN: The active sender fee-credit slot is settled again after
        // payload gas refunds are finalized. Preserve ordinary SSTORE pricing,
        // but make that one system-owned slot refund-ineligible so a payload
        // clear cannot retain a refund after settlement re-credits it.
        let suppress_evm_refund_delta =
            ee_type == ExecutionEnvironmentType::EVM && evm_original_override.is_some();
        let val_at_tx_start =
            evm_original_override.unwrap_or_else(|| addr_data.committed().value());
        let val_current = addr_data.current().value();
        // Use NEW write-extra only for the first cold write to a truly new slot.
        // Once the insertion cost has been paid, subsequent txs pay EXISTING.
        let is_new_slot = addr_data.element_properties().is_new_element()
            && addr_data
                .current()
                .metadata()
                .write_extra_charged_in_tx
                .is_none();

        // Two separate warmness flags:
        // - is_warm_access: EIP-2929 access warmness (any prior SLOAD or SSTORE) — for ergs
        // - is_cold_write_charged: cold write extra already paid this tx — for native
        let is_warm_access = is_warm_read.0;
        let is_cold_write_charged =
            addr_data.current().metadata().write_extra_charged_in_tx == Some(self.current_tx_id);

        self.resources_policy.charge_storage_write_extra(
            ee_type,
            val_at_tx_start,
            val_current,
            new_value,
            resources,
            is_warm_access,
            is_cold_write_charged,
            is_new_slot,
        )?;

        // Compute refund before mutating the cache, so val_at_tx_start and
        // val_current can stay borrowed from addr_data.
        let refund_counter_value = if suppress_evm_refund_delta {
            None
        } else {
            let mut refund_counter_value = self.evm_refunds_counter.value().clone();
            self.resources_policy.refund_for_storage_write(
                ee_type,
                val_at_tx_start,
                val_current,
                new_value,
                resources,
                &mut refund_counter_value,
            )?;
            Some(refund_counter_value)
        };

        // Detach owned old_value from addr_data's borrow before the update.
        let old_value = val_current.clone();
        let current_tx_id = self.current_tx_id;

        addr_data.update(|cache_record| {
            cache_record.update(|x, m| {
                *x = new_value.clone();
                if !is_cold_write_charged && new_value != &old_value {
                    m.write_extra_charged_in_tx = Some(current_tx_id);
                }
                Ok(())
            })
        })?;
        if let Some(refund_counter_value) = refund_counter_value {
            self.evm_refunds_counter.update(refund_counter_value);
        }

        Ok(old_value)
    }

    /// SYSCOIN: Read a bootloader-owned fee-ledger slot while charging native
    /// storage work but preserving EIP-2929 warmth and EIP-2200 metadata.
    pub fn apply_fee_ledger_read_impl(
        &mut self,
        key: &K,
        resources: &mut R,
        oracle: &mut impl IOOracle,
    ) -> Result<V, SystemError>
    where
        StorageAddress<EthereumIOTypesConfig>: From<K>,
    {
        let (addr_data, _) = Self::materialize_element(
            &mut self.cache,
            &mut self.resources_policy,
            self.current_tx_id,
            ExecutionEnvironmentType::NoEE,
            resources,
            key,
            oracle,
            EvmWarmthMode::Preserve,
        )?;
        Ok(addr_data.current().value().clone())
    }

    /// SYSCOIN: Compare-and-write a bootloader-owned fee-ledger slot. This
    /// updates public state and rollback history, charges native read/write
    /// work, and optionally rebases the payload's EVM-original value, but it
    /// never warms the slot or mutates the EVM refund counter. Exactly one
    /// rebase is permitted per transaction: the sender-credit precharge. Its
    /// bounded singleton history update replaces the skipped refund-counter
    /// update under the write's native-work allowance.
    pub fn apply_fee_ledger_write_impl(
        &mut self,
        key: &K,
        expected_current: &V,
        new_value: &V,
        rebase_evm_original: bool,
        oracle: &mut impl IOOracle,
        resources: &mut R,
    ) -> Result<(), SystemError>
    where
        StorageAddress<EthereumIOTypesConfig>: From<K>,
    {
        if rebase_evm_original && self.evm_original_override.value().is_some() {
            return Err(internal_error!(
                "fee-ledger EVM-original override already set in transaction"
            )
            .into());
        }

        let (mut addr_data, is_warm_read) = Self::materialize_element(
            &mut self.cache,
            &mut self.resources_policy,
            self.current_tx_id,
            ExecutionEnvironmentType::NoEE,
            resources,
            key,
            oracle,
            EvmWarmthMode::Preserve,
        )?;

        let val_current = addr_data.current().value();
        if val_current != expected_current {
            return Err(internal_error!("fee-ledger storage current value mismatch").into());
        }

        let val_at_tx_start = addr_data.committed().value();
        let is_new_slot = addr_data.element_properties().is_new_element()
            && addr_data
                .current()
                .metadata()
                .write_extra_charged_in_tx
                .is_none();
        let is_cold_write_charged =
            addr_data.current().metadata().write_extra_charged_in_tx == Some(self.current_tx_id);

        self.resources_policy.charge_storage_write_extra(
            ExecutionEnvironmentType::NoEE,
            val_at_tx_start,
            val_current,
            new_value,
            resources,
            is_warm_read.0,
            is_cold_write_charged,
            is_new_slot,
        )?;

        let old_value = val_current.clone();
        let current_tx_id = self.current_tx_id;
        addr_data.update(|cache_record| {
            cache_record.update(|value, metadata| {
                *value = new_value.clone();
                if !is_cold_write_charged && new_value != &old_value {
                    metadata.write_extra_charged_in_tx = Some(current_tx_id);
                }
                Ok(())
            })
        })?;

        if rebase_evm_original {
            // SYSCOIN: Infallible O(1) history update under the same frame as
            // the public write; both roll back through StorageSnapshotId.
            self.evm_original_override
                .update(Some((*key, new_value.clone())));
        }

        Ok(())
    }

    /// Clear state at specified address
    pub fn clear_state_impl(&mut self, address: impl AsRef<B160>) -> Result<(), SystemError>
    where
        K::Subspace: TyEq<B160>,
    {
        use core::ops::Bound::Included;
        let lower_bound = K::lower_bound(TyEq::rwi(*address.as_ref()));
        let upper_bound = K::upper_bound(TyEq::rwi(*address.as_ref()));
        self.cache
            .for_each_range((Included(&lower_bound), Included(&upper_bound)), |mut x| {
                x.update(|cache_record| {
                    cache_record.update(|v, _| {
                        *v = V::default();
                        Ok(())
                    })
                })
            })?;

        // SYSCOIN: A cleared account cannot retain a payload-original override
        // for one of its fee-ledger slots.
        let clear_override = self
            .evm_original_override
            .value()
            .and_then(Option::as_ref)
            .is_some_and(|(override_key, _)| {
                override_key >= &lower_bound && override_key <= &upper_bound
            });
        if clear_override {
            self.evm_original_override.update(None);
        }

        Ok(())
    }

    pub fn get_refund_counter_impl(&'_ self) -> &'_ R {
        self.evm_refunds_counter.value()
    }

    pub fn add_to_refund_counter_impl(&mut self, refund: R) -> Result<(), SystemError> {
        let mut t = self.get_refund_counter_impl().clone();
        t.add_ergs(refund.ergs());
        self.evm_refunds_counter.update(t);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_implementation::ethereum_storage_model::caches::full_storage_cache::EthereumStorageCache;
    use crate::system_implementation::flat_storage_model::cost_constants::{
        COLD_EXISTING_STORAGE_READ_NATIVE_COST, WARM_STORAGE_READ_NATIVE_COST,
    };
    use crate::system_implementation::flat_storage_model::storage_cache::NewStorageWithAccountPropertiesUnderHash;
    use crate::system_implementation::system::EthereumLikeStorageAccessCostModel;
    use core::iter::Empty;
    use evm_interpreter::{gas_constants::COLD_SLOAD_COST, ERGS_PER_GAS};
    use std::alloc::Global;
    use storage_models::common_structs::StorageCacheModel;
    use zk_ee::common_structs::WarmStorageKey;
    use zk_ee::memory::stack_implementations::vec_stack::VecStackFactory;
    use zk_ee::oracle::usize_serialization::{UsizeDeserializable, UsizeSerializable};
    use zk_ee::reference_implementations::{BaseResources, DecreasingNative};
    use zk_ee::system::{Computational, Ergs, Resource};
    use zk_ee::types_config::EthereumIOTypesConfig;
    use zk_ee::utils::Bytes32;

    type TestResources = BaseResources<DecreasingNative>;
    type TestStorage = GenericPubdataAwarePlainStorage<
        WarmStorageKey,
        Bytes32,
        Global,
        VecStackFactory,
        8,
        TestResources,
        EthereumLikeStorageAccessCostModel,
    >;

    struct UnusedOracle;

    impl IOOracle for UnusedOracle {
        type RawIterator<'a> = Empty<usize>;

        fn raw_query<'a, I: UsizeSerializable + UsizeDeserializable>(
            &'a mut self,
            _query_type: u32,
            _input: &I,
        ) -> Result<Self::RawIterator<'a>, InternalError> {
            panic!("pre-materialized test slot must not query the oracle")
        }
    }

    fn value(value: u64) -> Bytes32 {
        Bytes32::from_array(ruint::aliases::U256::from(value).to_be_bytes::<32>())
    }

    fn key() -> WarmStorageKey {
        WarmStorageKey {
            address: B160::from_limbs([0x1234, 0, 0]),
            key: value(7),
        }
    }

    fn other_credit_key() -> WarmStorageKey {
        WarmStorageKey {
            address: key().address,
            key: value(8),
        }
    }

    fn ordinary_key() -> WarmStorageKey {
        WarmStorageKey {
            address: B160::from_limbs([0x5678, 0, 0]),
            key: value(7),
        }
    }

    fn resources() -> TestResources {
        TestResources::from_ergs_and_native(
            Ergs(10_000_000 * ERGS_PER_GAS),
            DecreasingNative::from_computational(10_000_000),
        )
    }

    fn preload_key(storage: &mut TestStorage, storage_key: WarmStorageKey, initial: u64) {
        storage
            .cache
            .get_or_insert::<InternalError>(&storage_key, || {
                Ok((
                    CacheRecord::new(value(initial)),
                    CacheElementProperties::new(false, true),
                ))
            })
            .unwrap();
    }

    fn preload(storage: &mut TestStorage, initial: u64) {
        preload_key(storage, key(), initial);
    }

    fn storage_with_initial(initial: u64) -> TestStorage {
        let mut storage = TestStorage::new_from_parts(Global, EthereumLikeStorageAccessCostModel);
        preload(&mut storage, initial);
        storage.begin_new_tx();
        storage
    }

    fn exercise_cache_model_fee_ledger_semantics<C>(cache: &mut C)
    where
        C: StorageCacheModel<IOTypes = EthereumIOTypesConfig, Resources = TestResources>,
    {
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        let address = key().address;
        let storage_key = key().key;

        cache.begin_new_tx();
        cache
            .read(
                ExecutionEnvironmentType::EVM,
                &mut resources,
                &address,
                &storage_key,
                &mut oracle,
            )
            .unwrap();
        cache
            .fee_ledger_write(
                &mut resources,
                &address,
                &storage_key,
                &value(100),
                &value(40),
                true,
                &mut oracle,
            )
            .unwrap();
        let before_warm_read = resources.ergs().0;
        cache
            .read(
                ExecutionEnvironmentType::EVM,
                &mut resources,
                &address,
                &storage_key,
                &mut oracle,
            )
            .unwrap();
        assert_eq!(
            before_warm_read - resources.ergs().0,
            evm_interpreter::gas_constants::WARM_STORAGE_READ_COST * ERGS_PER_GAS
        );

        cache.begin_new_tx();
        assert_eq!(
            cache
                .fee_ledger_read(&mut resources, &address, &storage_key, &mut oracle,)
                .unwrap(),
            value(40)
        );
        let before_cold_evm_read = resources.ergs().0;
        cache
            .read(
                ExecutionEnvironmentType::EVM,
                &mut resources,
                &address,
                &storage_key,
                &mut oracle,
            )
            .unwrap();
        assert_eq!(
            before_cold_evm_read - resources.ergs().0,
            COLD_SLOAD_COST * ERGS_PER_GAS
        );

        let snapshot = cache.start_frame();
        cache
            .fee_ledger_write(
                &mut resources,
                &address,
                &storage_key,
                &value(40),
                &value(30),
                true,
                &mut oracle,
            )
            .unwrap();
        cache.finish_frame(Some(&snapshot)).unwrap();
        assert_eq!(
            cache
                .fee_ledger_read(&mut resources, &address, &storage_key, &mut oracle,)
                .unwrap(),
            value(40)
        );
    }

    // SYSCOIN: Both concrete storage caches must expose identical warmth,
    // native-admission and rollback behavior through the narrow trait path.
    #[test]
    fn fee_ledger_semantics_match_flat_and_ethereum_caches() {
        let mut flat_inner =
            TestStorage::new_from_parts(Global, EthereumLikeStorageAccessCostModel);
        preload(&mut flat_inner, 100);
        let mut flat = NewStorageWithAccountPropertiesUnderHash(flat_inner);
        exercise_cache_model_fee_ledger_semantics(&mut flat);

        let mut ethereum_inner =
            TestStorage::new_from_parts(Global, EthereumLikeStorageAccessCostModel);
        preload(&mut ethereum_inner, 100);
        let mut ethereum = EthereumStorageCache {
            slot_values: ethereum_inner,
        };
        exercise_cache_model_fee_ledger_semantics(&mut ethereum);
    }

    // SYSCOIN: A fee-ledger read pays native cold work but leaves an EVM-cold
    // slot cold; the following EVM read must still pay the full 2100 gas.
    #[test]
    fn fee_ledger_read_does_not_warm_evm_slot() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();

        assert_eq!(
            storage
                .apply_fee_ledger_read_impl(&key(), &mut resources, &mut oracle)
                .unwrap(),
            value(100)
        );
        let metadata = storage.cache.get(&key()).unwrap().current().metadata();
        assert_eq!(metadata.last_touched_in_tx, None);
        assert_eq!(
            metadata.native_read_extra_charged_in_tx,
            Some(storage.current_tx_id)
        );

        let before_ergs = resources.ergs().0;
        storage
            .apply_read_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &mut resources,
                &mut oracle,
            )
            .unwrap();
        assert_eq!(
            before_ergs - resources.ergs().0,
            COLD_SLOAD_COST * ERGS_PER_GAS
        );
    }

    // SYSCOIN: The default `None` marker cannot alias block-level tx ID zero.
    // The first pre-transaction-system read pays cold native work, and a
    // repeat at tx ID zero pays only the warm-read native component.
    #[test]
    fn native_read_marker_charges_cold_work_at_transaction_id_zero() {
        let mut storage = TestStorage::new_from_parts(Global, EthereumLikeStorageAccessCostModel);
        preload(&mut storage, 100);
        assert_eq!(storage.current_tx_id, TransactionId(0));
        assert_eq!(
            storage
                .cache
                .get(&key())
                .unwrap()
                .current()
                .metadata()
                .native_read_extra_charged_in_tx,
            None
        );

        let mut oracle = UnusedOracle;
        let mut resources = resources();
        let before_first = resources.native().as_u64();
        storage
            .apply_fee_ledger_read_impl(&key(), &mut resources, &mut oracle)
            .unwrap();
        assert_eq!(
            before_first - resources.native().as_u64(),
            WARM_STORAGE_READ_NATIVE_COST + COLD_EXISTING_STORAGE_READ_NATIVE_COST
        );
        assert_eq!(
            storage
                .cache
                .get(&key())
                .unwrap()
                .current()
                .metadata()
                .native_read_extra_charged_in_tx,
            Some(TransactionId(0))
        );

        let before_repeat = resources.native().as_u64();
        storage
            .apply_fee_ledger_read_impl(&key(), &mut resources, &mut oracle)
            .unwrap();
        assert_eq!(
            before_repeat - resources.native().as_u64(),
            WARM_STORAGE_READ_NATIVE_COST
        );
    }

    // SYSCOIN: An access-list/EVM warm marker that predates precharge must be
    // preserved exactly by fee-ledger reads and writes.
    #[test]
    fn fee_ledger_mutation_preserves_existing_evm_warmth_and_committed_value() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_read_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &mut resources,
                &mut oracle,
            )
            .unwrap();
        let warm_tx = storage
            .cache
            .get(&key())
            .unwrap()
            .current()
            .metadata()
            .last_touched_in_tx;

        storage
            .apply_fee_ledger_read_impl(&key(), &mut resources, &mut oracle)
            .unwrap();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();

        let item = storage.cache.get(&key()).unwrap();
        assert_eq!(item.current().metadata().last_touched_in_tx, warm_tx);
        assert_eq!(*item.committed().value(), value(100));
        assert_eq!(*item.current().value(), value(40));
        assert_eq!(
            storage
                .evm_original_override
                .value()
                .and_then(Option::as_ref),
            Some(&(key(), value(40)))
        );
    }

    // SYSCOIN: Rebased EVM-original values prevent refund underflow on an
    // exact-credit restore and suppress the dirty-reset refund on partial restore.
    #[test]
    fn fee_precharge_rebases_eip2200_original_for_payload_writes() {
        for (initial, post_precharge) in [(100, 0), (100, 40)] {
            let mut storage = storage_with_initial(initial);
            let mut oracle = UnusedOracle;
            let mut resources = resources();
            storage
                .apply_fee_ledger_write_impl(
                    &key(),
                    &value(initial),
                    &value(post_precharge),
                    true,
                    &mut oracle,
                    &mut resources,
                )
                .unwrap();
            storage
                .apply_write_impl(
                    ExecutionEnvironmentType::EVM,
                    &key(),
                    &value(initial),
                    &mut oracle,
                    &mut resources,
                )
                .unwrap();
            assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
        }

        // SYSCOIN: Clearing the active fee slot cannot retain a refund because
        // post-payload settlement may re-credit the same slot.
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(0),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(0),
                &value(10),
                false,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
    }

    // SYSCOIN: The post-precharge value is the payload's clean EVM-original,
    // not a dirty mutation of the pre-transaction committed value. A cold
    // nonzero-to-nonzero SSTORE therefore costs 100 warm-read + 2,000 cold-read
    // extra + 2,800 reset-extra + the 100 cold-SSTORE discrepancy = 5,000 gas.
    #[test]
    fn fee_precharge_rebase_uses_clean_sstore_pricing() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(90),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();

        let before_ergs = resources.ergs().0;
        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(100),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(before_ergs - resources.ergs().0, 5_000 * ERGS_PER_GAS);
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
    }

    // SYSCOIN: Public value, native markers and the singleton EVM-original
    // rebase all follow the same outer frame rollback.
    #[test]
    fn fee_ledger_rebase_rolls_back_with_public_state() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        let snapshot = storage.start_frame();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(
            storage
                .evm_original_override
                .value()
                .and_then(Option::as_ref),
            Some(&(key(), value(40)))
        );

        storage.finish_frame_impl(Some(&snapshot)).unwrap();
        let item = storage.cache.get(&key()).unwrap();
        assert_eq!(*item.current().value(), value(100));
        assert!(storage.evm_original_override.value().is_none());
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
    }

    // SYSCOIN: One L2 transaction has exactly one sender-credit precharge.
    // A duplicate rebase fails before charging or mutating either history.
    #[test]
    fn fee_ledger_rebase_singleton_rejects_duplicate_without_side_effects() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        let resources_after_first = resources.clone();

        assert!(storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(40),
                &value(30),
                true,
                &mut oracle,
                &mut resources,
            )
            .is_err());
        assert_eq!(resources, resources_after_first);
        assert_eq!(
            *storage.cache.get(&key()).unwrap().current().value(),
            value(40)
        );
        assert_eq!(
            storage
                .evm_original_override
                .value()
                .and_then(Option::as_ref),
            Some(&(key(), value(40)))
        );
    }

    // SYSCOIN: Account-state clearing invalidates an override in that address
    // range, and a nested rollback restores the public value and singleton.
    #[test]
    fn clear_state_and_rollback_track_fee_ledger_rebase_singleton() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();

        let snapshot = storage.start_frame();
        storage.clear_state_impl(Box::new(key().address)).unwrap();
        assert_eq!(
            *storage.cache.get(&key()).unwrap().current().value(),
            value(0)
        );
        assert!(storage
            .evm_original_override
            .value()
            .and_then(Option::as_ref)
            .is_none());

        storage.finish_frame_impl(Some(&snapshot)).unwrap();
        assert_eq!(
            *storage.cache.get(&key()).unwrap().current().value(),
            value(40)
        );
        assert_eq!(
            storage
                .evm_original_override
                .value()
                .and_then(Option::as_ref),
            Some(&(key(), value(40)))
        );
    }

    // SYSCOIN: Clearing the rebased account records an inner `None`, but the
    // singleton history is still occupied for this transaction. A second
    // rebase must fail before charging resources or recreating public state.
    #[test]
    fn fee_ledger_rebase_stays_consumed_after_account_clear() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        storage.clear_state_impl(Box::new(key().address)).unwrap();
        let resources_after_clear = resources.clone();

        assert!(storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(0),
                &value(30),
                true,
                &mut oracle,
                &mut resources,
            )
            .is_err());
        assert_eq!(resources, resources_after_clear);
        assert_eq!(
            *storage.cache.get(&key()).unwrap().current().value(),
            value(0)
        );
        assert!(matches!(storage.evm_original_override.value(), Some(None)));
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
    }

    // SYSCOIN: The precharge lives outside the main-body frame. Reverting a
    // payload SSTORE must retain the post-precharge public/original value and
    // discard only the payload value/refund before settlement continues.
    #[test]
    fn payload_rollback_retains_precharge_rebase_for_settlement() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();

        let payload_snapshot = storage.start_frame();
        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(0),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
        storage.finish_frame_impl(Some(&payload_snapshot)).unwrap();

        let item = storage.cache.get(&key()).unwrap();
        assert_eq!(*item.current().value(), value(40));
        assert_eq!(
            storage
                .evm_original_override
                .value()
                .and_then(Option::as_ref),
            Some(&(key(), value(40)))
        );
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());

        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(40),
                &value(50),
                false,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(
            *storage.cache.get(&key()).unwrap().current().value(),
            value(50)
        );
    }

    // SYSCOIN: The active fee slot remains refund-ineligible across every
    // payload mutation because settlement can mutate it after finalization.
    #[test]
    fn active_fee_slot_clear_then_restore_is_refund_ineligible() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(90),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(0),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(90),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
    }

    // SYSCOIN: Refund suppression is scoped to the exact active sender-credit
    // key and preserves refunds already earned by every other storage key.
    #[test]
    fn active_fee_slot_preserves_unrelated_storage_refunds() {
        let mut storage = TestStorage::new_from_parts(Global, EthereumLikeStorageAccessCostModel);
        preload_key(&mut storage, key(), 100);
        preload_key(&mut storage, other_credit_key(), 100);
        preload_key(&mut storage, ordinary_key(), 100);
        storage.begin_new_tx();

        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(90),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();

        for unrelated_key in [other_credit_key(), ordinary_key()] {
            storage
                .apply_write_impl(
                    ExecutionEnvironmentType::EVM,
                    &unrelated_key,
                    &value(0),
                    &mut oracle,
                    &mut resources,
                )
                .unwrap();
        }
        let unrelated_refunds = Ergs(9_600 * ERGS_PER_GAS);
        assert_eq!(storage.get_refund_counter_impl().ergs(), unrelated_refunds);

        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(0),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(90),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(storage.get_refund_counter_impl().ergs(), unrelated_refunds);
    }

    // SYSCOIN: Committing a transaction preserves the public precharge while
    // resetting the per-tx EVM-original override before the next payload.
    #[test]
    fn fee_ledger_override_is_committed_but_stale_next_transaction() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(100),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        let first_tx_id = storage.current_tx_id;
        storage.begin_new_tx();
        assert_ne!(storage.current_tx_id, first_tx_id);
        assert_eq!(
            *storage.cache.get(&key()).unwrap().committed().value(),
            value(40)
        );
        assert!(storage.evm_original_override.value().is_none());
        storage
            .apply_write_impl(
                ExecutionEnvironmentType::EVM,
                &key(),
                &value(100),
                &mut oracle,
                &mut resources,
            )
            .unwrap();
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
    }

    // SYSCOIN: Stale callers cannot overwrite the fee ledger or create an
    // EVM-original override/refund side effect.
    #[test]
    fn fee_ledger_write_fails_closed_on_expected_current_mismatch() {
        let mut storage = storage_with_initial(100);
        let mut oracle = UnusedOracle;
        let mut resources = resources();
        assert!(storage
            .apply_fee_ledger_write_impl(
                &key(),
                &value(99),
                &value(40),
                true,
                &mut oracle,
                &mut resources,
            )
            .is_err());
        let item = storage.cache.get(&key()).unwrap();
        assert_eq!(*item.current().value(), value(100));
        assert!(storage.evm_original_override.value().is_none());
        assert_eq!(storage.get_refund_counter_impl().ergs(), Ergs::empty());
    }
}
