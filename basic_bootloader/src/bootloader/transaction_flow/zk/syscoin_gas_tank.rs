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
use zk_ee::execution_environment_type::ExecutionEnvironmentType;
use zk_ee::system::errors::system::SystemError;
use zk_ee::system::{
    EthereumLikeTypes, IOSubsystem, IOSubsystemExt, Resource, System, SystemTypes,
};
use zk_ee::utils::Bytes32;

use super::syscoin_edge_da::syscoin_gas_tank_address;

/// Slot of `mapping(address => uint256) credit` in `ZkSysGasTank`.
const CREDIT_MAPPING_SLOT: u8 = 0;
/// Slot of `uint256 totalCredits` in `ZkSysGasTank`.
const TOTAL_CREDITS_SLOT: u8 = 1;

/// The gas tank is active only when the deployment bakes a nonzero address.
#[inline(always)]
pub fn gas_tank_enabled() -> bool {
    syscoin_gas_tank_address() != B160::ZERO
}

/// Solidity mapping slot: keccak256(pad32(account) || pad32(CREDIT_MAPPING_SLOT)).
fn credit_slot_key(account: &B160) -> Bytes32 {
    use crypto::MiniDigest;
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(&account.to_be_bytes::<20>());
    preimage[63] = CREDIT_MAPPING_SLOT;
    let mut hasher = crypto::sha3::Keccak256::new();
    hasher.update(preimage);
    Bytes32::from_array(hasher.finalize())
}

fn total_credits_key() -> Bytes32 {
    let mut key = [0u8; 32];
    key[31] = TOTAL_CREDITS_SLOT;
    Bytes32::from_array(key)
}

fn read_tank_slot<S: EthereumLikeTypes>(
    system: &mut System<S>,
    key: &Bytes32,
) -> Result<U256, SystemError>
where
    S::IO: IOSubsystemExt,
{
    // Tank slot accesses are part of fee mechanics: like the native fee
    // balance updates they are not metered against transaction gas. The
    // resulting storage diffs are budgeted by the intrinsic pubdata formula
    // (see `SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA`). The computational native
    // cost runs on a local unmetered pool: it is a small constant per
    // transaction (at most nine slot accesses and three keccaks across
    // precharge, refund and settlement) and is offset by the intrinsic-native
    // budget of the native-balance fee updates that tank payment skips.
    let mut inf_resources = <S as SystemTypes>::Resources::FORMAL_INFINITE;
    let value = system.io.storage_read::<false>(
        ExecutionEnvironmentType::NoEE,
        &mut inf_resources,
        &syscoin_gas_tank_address(),
        key,
    )?;
    Ok(U256::from_be_bytes(value.as_u8_array()))
}

fn write_tank_slot<S: EthereumLikeTypes>(
    system: &mut System<S>,
    key: &Bytes32,
    value: &U256,
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    let mut inf_resources = <S as SystemTypes>::Resources::FORMAL_INFINITE;
    system.io.storage_write::<false>(
        ExecutionEnvironmentType::NoEE,
        &mut inf_resources,
        &syscoin_gas_tank_address(),
        key,
        &Bytes32::from_array(value.to_be_bytes::<32>()),
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
) -> Result<bool, SystemError>
where
    S::IO: IOSubsystemExt,
{
    if !gas_tank_enabled() || fee.is_zero() {
        return Ok(false);
    }

    let credit_key = credit_slot_key(from);
    let credit = read_tank_slot(system, &credit_key)?;
    let Some(new_credit) = credit.checked_sub(*fee) else {
        return Ok(false);
    };

    // `totalCredits >= credit[account]` is an invariant of the canonical tank
    // contract. A violation means the configured address does not hold the
    // canonical contract, which is a deployment defect.
    let total = read_tank_slot(system, &total_credits_key())?;
    if total < credit {
        return Err(zk_ee::internal_error!("gas tank totalCredits below account credit").into());
    }

    write_tank_slot(system, &credit_key, &new_credit)?;
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
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    if amount.is_zero() {
        return Ok(());
    }

    let credit_key = credit_slot_key(account);
    let credit = read_tank_slot(system, &credit_key)?;
    // Credits are backed 1:1 by zkSYS held in the tank, whose supply is
    // hard-capped far below 2^256, so overflow implies a corrupted deployment.
    let new_credit = credit
        .checked_add(*amount)
        .ok_or(zk_ee::internal_error!("gas tank credit overflow"))?;

    write_tank_slot(system, &credit_key, &new_credit)?;
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
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    if amount.is_zero() {
        return Ok(());
    }

    let total_key = total_credits_key();
    let total = read_tank_slot(system, &total_key)?;
    // Unreachable under the canonical contract: the in-flight precharge keeps
    // `totalCredits >= fee_to_prepay >= burned fee` until settlement.
    let new_total = total
        .checked_sub(*amount)
        .ok_or(zk_ee::internal_error!("gas tank totalCredits burn underflow"))?;

    write_tank_slot(system, &total_key, &new_total)?;
    Ok(())
}
