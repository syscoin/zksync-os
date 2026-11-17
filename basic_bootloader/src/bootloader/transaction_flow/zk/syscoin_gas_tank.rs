//! SYSCOIN: protocol gas-tank support for paying L2 fees in zkSYS.
//!
//! Accounts prepay gas by depositing zkSYS into the `ZkSysGasTank` contract
//! (zksync-os-server `contracts/src/zksys/ZkSysGasTank.sol`). Funding the tank
//! is the opt-in: whenever the sender's tank credit covers the full fee
//! prepayment of a transaction, the bootloader debits the tank instead of the
//! native (SYS) balance, at a fixed 1:1 rate (the tank contract enforces that
//! the token uses native 18-decimals). Refunds and the operator tip are
//! settled against the same ledger. The base-fee portion is never credited to
//! anyone, so it reduces `totalCredits` while the backing zkSYS stays in the
//! tank contract, accumulating as surplus that `burnSurplus()` destroys
//! permissionlessly.
//!
//! Ledger accounting is ordered so the tank is never transiently insolvent:
//! precharge debits only the sender's `credit` and leaves `totalCredits`
//! untouched; post-execution settlement credits the refund and operator tip
//! to their accounts and then reduces `totalCredits` exactly once by the
//! burned portion (precharge minus refund minus tip). Because `totalCredits`
//! is never transiently lowered by the full precharge,
//! `token.balanceOf(tank) - totalCredits` cannot expose the pending
//! refund/tip as burnable surplus mid-transaction (e.g. a tank-paid tx that
//! calls `burnSurplus()` during its own execution), which preserves the
//! solvency invariant `totalCredits <= token.balanceOf(tank)`.
//!
//! Native admission checks (node mempool and bootloader validation) are
//! intentionally unchanged: senders must always hold SYS covering
//! `value + gas_limit * max_fee`, which keeps standard wallets and RPC
//! estimation working. When the tank credit is insufficient for the full fee,
//! fee charging falls back to the pre-verified native path, so no new
//! rejection paths are introduced.
//!
//! The storage layout of the tank contract is pinned (the contract is
//! non-upgradeable by construction):
//! - slot 0: `mapping(address => uint256) credit`
//! - slot 1: `uint256 totalCredits`

use ruint::aliases::{B160, U256};
use zk_ee::system::errors::system::SystemError;
use zk_ee::system::{Computational, EthereumLikeTypes, IOSubsystemExt, Resources, System};
use zk_ee::utils::Bytes32;

use super::syscoin_edge_da::syscoin_gas_tank_address;
use crate::bootloader::constants::{
    SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST, SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA,
    SYSCOIN_GAS_TANK_MAPPING_KEY_KECCAK_NATIVE_COST,
    SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST,
};
use crate::bootloader::transaction_flow::gas_helpers::ResourcesForTx;

/// Slot of `mapping(address => uint256) credit` in `ZkSysGasTank`.
const CREDIT_MAPPING_SLOT: u8 = 0;
/// Slot of `uint256 totalCredits` in `ZkSysGasTank`.
const TOTAL_CREDITS_SLOT: u8 = 1;

// SYSCOIN: Conditional gas-tank branches must never turn a transaction that
// already passed native-fee validation into an intrinsic-overflow rejection.
// Returning `None` lets the caller retain the resources/formula of the last
// completed stage and select native fallback.
#[inline(always)]
fn checked_intrinsic_branch_totals(
    current_computational_native: u64,
    current_pubdata: u64,
    additional_computational_native: u64,
    additional_pubdata: u64,
) -> Option<(u64, u64)> {
    Some((
        current_computational_native.checked_add(additional_computational_native)?,
        current_pubdata.checked_add(additional_pubdata)?,
    ))
}

/// The gas tank is active only when the deployment bakes a nonzero address.
#[inline(always)]
pub fn gas_tank_enabled() -> bool {
    syscoin_gas_tank_address() != B160::ZERO
}

/// Solidity mapping slot: keccak256(pad32(account) || pad32(CREDIT_MAPPING_SLOT)).
fn credit_slot_key<R: Resources>(
    account: &B160,
    resources: &mut R,
) -> Result<Bytes32, SystemError> {
    // SYSCOIN: Mapping-key Keccaks are intrinsic work, not an unmetered local
    // computation. Charge the transaction tracker before hashing.
    resources.charge(&R::from_native(R::Native::from_computational(
        SYSCOIN_GAS_TANK_MAPPING_KEY_KECCAK_NATIVE_COST,
    )))?;
    use crypto::MiniDigest;
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(&account.to_be_bytes::<20>());
    preimage[63] = CREDIT_MAPPING_SLOT;
    let mut hasher = crypto::sha3::Keccak256::new();
    hasher.update(preimage);
    Ok(Bytes32::from_array(hasher.finalize()))
}

fn total_credits_key() -> Bytes32 {
    let mut key = [0u8; 32];
    key[31] = TOTAL_CREDITS_SLOT;
    Bytes32::from_array(key)
}

fn read_tank_slot<S: EthereumLikeTypes>(
    system: &mut System<S>,
    key: &Bytes32,
    resources: &mut S::Resources,
) -> Result<U256, SystemError>
where
    S::IO: IOSubsystemExt,
{
    // SYSCOIN: The narrow fee-ledger read charges native work while preserving
    // EVM warmth/refund metadata. The caller supplies the tx intrinsic tracker.
    let value = system
        .io
        .fee_ledger_storage_read(resources, &syscoin_gas_tank_address(), key)?;
    Ok(U256::from_be_bytes(value.as_u8_array()))
}

fn write_tank_slot<S: EthereumLikeTypes>(
    system: &mut System<S>,
    key: &Bytes32,
    expected_current: &U256,
    value: &U256,
    rebase_evm_original: bool,
    resources: &mut S::Resources,
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    // SYSCOIN: Fail closed if the value read by fee logic is no longer current;
    // special writes never touch the EVM refund counter.
    system.io.fee_ledger_storage_write(
        resources,
        &syscoin_gas_tank_address(),
        key,
        &Bytes32::from_array(expected_current.to_be_bytes::<32>()),
        &Bytes32::from_array(value.to_be_bytes::<32>()),
        rebase_evm_original,
    )
}

/// Attempt to charge `fee` from the sender's gas-tank credit.
///
/// Returns `Ok(true)` and debits only the sender's `credit` (never
/// `totalCredits`) iff the credit covers the full fee. Otherwise leaves the
/// tank untouched and returns `Ok(false)` so the caller falls back to the
/// (pre-verified) native fee path.
///
/// `totalCredits` is deliberately left unchanged here: the full precharge is
/// not yet known to be burned (the refund and operator tip are settled after
/// execution), so lowering `totalCredits` now would transiently expose the
/// pending refund/tip as burnable surplus. Settlement reduces `totalCredits`
/// once, by the burned fee, in `debit_gas_tank_total_credits`.
pub fn try_precharge_from_gas_tank<S: EthereumLikeTypes>(
    system: &mut System<S>,
    from: &B160,
    fee: &U256,
    is_service: bool,
    native_per_gas: u64,
    intrinsic_resources: &mut S::Resources,
    tx_resources: &mut ResourcesForTx<S>,
    native_per_pubdata: u64,
    intrinsic_computational_native: &mut u64,
    intrinsic_pubdata: &mut u64,
) -> Result<bool, SystemError>
where
    S::IO: IOSubsystemExt,
{
    // SYSCOIN: Stage 1 is entirely dynamic. Service/free-native/zero-fee paths
    // neither probe nor reserve any tank overhead.
    if !gas_tank_enabled() || is_service || native_per_gas == 0 || fee.is_zero() {
        return Ok(false);
    }

    let Some((probe_intrinsic_native, _)) = checked_intrinsic_branch_totals(
        *intrinsic_computational_native,
        *intrinsic_pubdata,
        SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST,
        0,
    ) else {
        // SYSCOIN: The pre-verified native path remains valid; no probe work or
        // conditional reservation has happened yet.
        return Ok(false);
    };
    if !tx_resources.try_reserve_conditional_intrinsic(
        native_per_pubdata,
        SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST,
        0,
    ) {
        // SYSCOIN: No work was performed, so native fallback retains the base
        // formula and resources exactly.
        return Ok(false);
    }
    *intrinsic_computational_native = probe_intrinsic_native;

    // SYSCOIN: Stage P: one mapping Keccak and one read-only credit probe.
    let credit_key = credit_slot_key(from, intrinsic_resources)?;
    let credit = read_tank_slot(system, &credit_key, intrinsic_resources)?;
    let Some(new_credit) = credit.checked_sub(*fee) else {
        return Ok(false);
    };

    // SYSCOIN: Only a credit-eligible transaction reserves D + 198 bytes. The
    // cloned, withheld-first reservation is atomic; failure leaves the P-only
    // fallback budget intact and selects the already-validated native path.
    let Some((success_intrinsic_native, success_intrinsic_pubdata)) =
        checked_intrinsic_branch_totals(
            *intrinsic_computational_native,
            *intrinsic_pubdata,
            SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST,
            SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA,
        )
    else {
        // SYSCOIN: Stage P is already accounted for, so fallback retains
        // base+P and does not reject an otherwise valid native-paid tx.
        return Ok(false);
    };
    if !tx_resources.try_reserve_conditional_intrinsic(
        native_per_pubdata,
        SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST,
        SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA,
    ) {
        return Ok(false);
    }

    // `totalCredits >= credit[account]` is an invariant of the canonical tank
    // contract. A violation means the configured address does not hold the
    // canonical contract, which is a deployment defect.
    let total = read_tank_slot(system, &total_credits_key(), intrinsic_resources)?;
    if total < credit {
        return Err(zk_ee::internal_error!("gas tank totalCredits below account credit").into());
    }

    write_tank_slot(
        system,
        &credit_key,
        &credit,
        &new_credit,
        true,
        intrinsic_resources,
    )?;
    *intrinsic_computational_native = success_intrinsic_native;
    *intrinsic_pubdata = success_intrinsic_pubdata;
    Ok(true)
}

/// Credit `amount` to `account`'s tank balance (gas refund or operator tip)
/// without touching `totalCredits`.
///
/// The matching `totalCredits` bookkeeping is a single burn in
/// `debit_gas_tank_total_credits`; keeping the two apart is what preserves the
/// solvency invariant across the precharge/settlement window (see the module
/// docs).
pub fn credit_gas_tank_account_only<S: EthereumLikeTypes>(
    system: &mut System<S>,
    account: &B160,
    amount: &U256,
    intrinsic_resources: &mut S::Resources,
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    if amount.is_zero() {
        return Ok(());
    }

    let credit_key = credit_slot_key(account, intrinsic_resources)?;
    let credit = read_tank_slot(system, &credit_key, intrinsic_resources)?;
    // Credits are backed 1:1 by zkSYS held in the tank, whose supply is
    // hard-capped far below 2^256, so overflow implies a corrupted deployment.
    let new_credit = credit
        .checked_add(*amount)
        .ok_or(zk_ee::internal_error!("gas tank credit overflow"))?;

    write_tank_slot(
        system,
        &credit_key,
        &credit,
        &new_credit,
        false,
        intrinsic_resources,
    )?;
    Ok(())
}

/// Reduce `totalCredits` by `amount` (the burned portion of a tank-paid fee:
/// precharge minus refund minus operator tip).
///
/// This is the only place `totalCredits` shrinks for tank payments. The
/// backing zkSYS stays in the tank contract, so the burned amount becomes
/// surplus (`token.balanceOf(tank) - totalCredits`) that `burnSurplus()`
/// destroys permissionlessly.
pub fn debit_gas_tank_total_credits<S: EthereumLikeTypes>(
    system: &mut System<S>,
    amount: &U256,
    intrinsic_resources: &mut S::Resources,
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    if amount.is_zero() {
        return Ok(());
    }

    let total_key = total_credits_key();
    let total = read_tank_slot(system, &total_key, intrinsic_resources)?;
    // Unreachable under the canonical contract: the in-flight precharge keeps
    // `totalCredits >= fee_to_prepay >= burned fee` until settlement.
    let new_total = total.checked_sub(*amount).ok_or(zk_ee::internal_error!(
        "gas tank totalCredits burn underflow"
    ))?;

    write_tank_slot(
        system,
        &total_key,
        &total,
        &new_total,
        false,
        intrinsic_resources,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::checked_intrinsic_branch_totals;
    use crate::bootloader::constants::{
        SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST, SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA,
        SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST,
    };

    // SYSCOIN: Either counter overflowing must select the caller's native
    // fallback branch instead of creating a new transaction rejection.
    #[test]
    fn conditional_intrinsic_counter_overflow_selects_fallback() {
        assert_eq!(
            checked_intrinsic_branch_totals(10, 20, 3, 4),
            Some((13, 24))
        );
        // Stage P overflow: fallback retains the unchanged base counters.
        assert!(checked_intrinsic_branch_totals(
            u64::MAX - SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST + 1,
            20,
            SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST,
            0,
        )
        .is_none());
        // Stage D native overflow: fallback retains the already-accounted P.
        assert!(checked_intrinsic_branch_totals(
            u64::MAX - SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST + 1,
            20,
            SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST,
            SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA,
        )
        .is_none());
        // Stage D pubdata overflow has the same P-only fallback semantics.
        assert!(checked_intrinsic_branch_totals(
            10,
            u64::MAX - SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA + 1,
            SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST,
            SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA,
        )
        .is_none());
    }
}
