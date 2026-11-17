// SYSCOIN: Full-transaction fixtures for zkSYS gas-tank selection, settlement,
// dynamic intrinsic accounting, and native-fallback atomicity.

use rig::alloy::consensus::TxEip1559;
use rig::alloy::primitives::{address, Address, TxKind};
use rig::basic_bootloader::bootloader::constants::{
    SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST, SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA,
    SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST,
};
use rig::basic_bootloader::bootloader::transaction_flow::gas_helpers::{
    calculate_l2_tx_intrinsic_computational_native_resources, L2TxIntrinsicNativeInput,
};
use rig::basic_bootloader::bootloader::transaction_flow::zk::syscoin_edge_da::syscoin_gas_tank_address;
use rig::basic_bootloader::bootloader::transaction_flow::zk::syscoin_gas_tank::gas_tank_enabled;
use rig::crypto::sha3::Keccak256;
use rig::crypto::MiniDigest;
use rig::forward_system::run::convert_alloy::{FromAlloy, IntoAlloy};
use rig::ruint::aliases::{B160, B256, U256};
use rig::{testing_signer, BlockContext, BlockOutput, TestingFramework};
use zksync_os_tests_common::zksync_tx::ZKsyncTxEnvelope;

const CHAIN_ID: u64 = 37;
const SUCCESS_GAS_LIMIT: u64 = 100_000;
const FALLBACK_GAS_LIMIT: u64 = 21_000;
const INITIAL_NATIVE_BALANCE: u64 = 1_000_000_000_000_000;
const COINBASE_INITIAL_NATIVE_BALANCE: u64 = 1;
const COINBASE: Address = address!("000000000000000000000000000000000000c01b");
const TARGET: Address = address!("0000000000000000000000000000000000001002");

fn tank_address() -> Address {
    assert!(
        gas_tank_enabled(),
        "fixture requires the baked gas-tank address"
    );
    syscoin_gas_tank_address().into_alloy()
}

fn credit_slot(account: Address) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(account.as_slice());

    let mut hasher = Keccak256::new();
    hasher.update(preimage);
    U256::from_be_bytes(hasher.finalize())
}

fn total_credits_slot() -> U256 {
    U256::ONE
}

fn storage_value(tester: &mut TestingFramework, key: U256) -> U256 {
    tester
        .get_storage_slot(&tank_address(), key)
        .map(|value| value.into_u256_be())
        .unwrap_or(U256::ZERO)
}

fn base_intrinsic_native() -> u64 {
    calculate_l2_tx_intrinsic_computational_native_resources(&L2TxIntrinsicNativeInput::default())
}

fn gas_price_for_native_remaining(gas_limit: u64, native_remaining_after_base: u64) -> u64 {
    base_intrinsic_native()
        .checked_add(native_remaining_after_base)
        .expect("test native budget must fit u64")
        .div_ceil(gas_limit)
}

fn make_tx(gas_limit: u64, gas_price: u64, base_fee: u64) -> ZKsyncTxEnvelope {
    let signer = testing_signer(0);
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        max_fee_per_gas: gas_price.into(),
        max_priority_fee_per_gas: gas_price
            .checked_sub(base_fee)
            .expect("base fee must not exceed gas price")
            .into(),
        gas_limit,
        to: TxKind::Call(TARGET),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Default::default(),
    };
    ZKsyncTxEnvelope::from_eth_tx(tx, signer)
}

fn run_scenario(
    gas_limit: u64,
    gas_price: u64,
    base_fee: u64,
    sender_credit: U256,
    total_credits: U256,
) -> (TestingFramework, BlockOutput) {
    let sender = testing_signer(0).address();
    let block_context = BlockContext {
        eip1559_basefee: U256::from(base_fee),
        native_price: U256::ONE,
        pubdata_price: U256::ZERO,
        coinbase: B160::from_alloy(COINBASE),
        ..Default::default()
    };

    let mut tester = TestingFramework::new()
        .with_balance(sender, U256::from(INITIAL_NATIVE_BALANCE))
        .with_balance(COINBASE, U256::from(COINBASE_INITIAL_NATIVE_BALANCE))
        .with_balance(TARGET, U256::ONE)
        .with_storage_slot(
            tank_address(),
            credit_slot(sender),
            B256::from(sender_credit),
        )
        .with_storage_slot(
            tank_address(),
            total_credits_slot(),
            B256::from(total_credits),
        )
        .with_block_context(block_context);
    let output = tester.execute_block(vec![make_tx(gas_limit, gas_price, base_fee)]);
    (tester, output)
}

fn accepted_tx(output: &BlockOutput) -> &rig::zksync_os_interface::types::TxOutput {
    let tx = output.tx_results[0]
        .as_ref()
        .expect("transaction must pass bootloader validation");
    assert!(
        tx.is_success(),
        "transaction must execute successfully: {tx:?}"
    );
    tx
}

fn assert_native_fee_payment(tester: &mut TestingFramework, output: &BlockOutput, gas_price: u64) {
    let sender = testing_signer(0).address();
    let paid = U256::from(accepted_tx(output).gas_used) * U256::from(gas_price);
    assert_eq!(
        tester.get_balance(&sender),
        U256::from(INITIAL_NATIVE_BALANCE) - paid,
        "native fallback must settle the fee from the sender"
    );
    assert_eq!(
        tester.get_balance(&COINBASE),
        U256::from(COINBASE_INITIAL_NATIVE_BALANCE) + paid,
        "native fallback must settle the fee to the operator"
    );
}

#[test]
fn gas_tank_success_settles_ledger_and_selects_dynamic_intrinsics() {
    // SYSCOIN: Give the tx ample main-native budget so both P and D are
    // reserved, while deriving the price from the same consensus formulas.
    let success_delta = SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST
        + SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST;
    let gas_price = gas_price_for_native_remaining(SUCCESS_GAS_LIMIT, success_delta + 2_000_000);
    let base_fee = gas_price / 2;
    assert!(base_fee > 0 && base_fee < gas_price);

    let fee_to_prepay = U256::from(gas_price) * U256::from(SUCCESS_GAS_LIMIT);
    let initial_credit = fee_to_prepay + U256::from(1_000_000u64);
    let (mut tank_tester, tank_output) = run_scenario(
        SUCCESS_GAS_LIMIT,
        gas_price,
        base_fee,
        initial_credit,
        initial_credit,
    );
    let tank_tx = accepted_tx(&tank_output);

    // Use an otherwise identical insufficient-credit execution as the base+P
    // control. The successful branch must add exactly D and 198 bytes to both
    // the transaction and block counters.
    let insufficient_credit = fee_to_prepay - U256::ONE;
    let (mut fallback_tester, fallback_output) = run_scenario(
        SUCCESS_GAS_LIMIT,
        gas_price,
        base_fee,
        insufficient_credit,
        insufficient_credit,
    );
    let fallback_tx = accepted_tx(&fallback_output);
    assert_eq!(
        tank_tx.computational_native_used,
        fallback_tx.computational_native_used
            + SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST,
        "tank success must select base+P+D rather than base+P"
    );
    assert_eq!(
        tank_tx.pubdata_used,
        fallback_tx.pubdata_used + SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA
    );
    assert_eq!(
        tank_output.computational_native_used,
        fallback_output.computational_native_used
            + SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST
    );
    assert_eq!(
        tank_output.pubdata_used,
        fallback_output.pubdata_used + SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA
    );
    assert_eq!(SYSCOIN_GAS_TANK_INTRINSIC_PUBDATA, 198);

    let refund = U256::from(SUCCESS_GAS_LIMIT - tank_tx.gas_used) * U256::from(gas_price);
    let operator_tip = U256::from(tank_tx.gas_used) * U256::from(gas_price - base_fee);
    let burned = fee_to_prepay - refund - operator_tip;
    let expected_sender_credit = initial_credit - fee_to_prepay + refund;
    let expected_total_credits = initial_credit - burned;

    assert_eq!(
        storage_value(&mut tank_tester, credit_slot(testing_signer(0).address())),
        expected_sender_credit
    );
    assert_eq!(
        storage_value(&mut tank_tester, credit_slot(COINBASE)),
        operator_tip
    );
    assert_eq!(
        storage_value(&mut tank_tester, total_credits_slot()),
        expected_total_credits
    );
    assert_eq!(
        expected_sender_credit + operator_tip,
        expected_total_credits
    );
    assert_eq!(
        tank_tester.get_balance(&testing_signer(0).address()),
        U256::from(INITIAL_NATIVE_BALANCE),
        "tank settlement must not debit the sender's native balance"
    );
    assert_eq!(
        tank_tester.get_balance(&COINBASE),
        U256::from(COINBASE_INITIAL_NATIVE_BALANCE),
        "tank settlement must not credit native fees to the operator"
    );

    // SYSCOIN: An insufficient-credit P-only fallback must not mutate any
    // tank slot and must retain the ordinary native settlement path.
    assert_eq!(
        storage_value(
            &mut fallback_tester,
            credit_slot(testing_signer(0).address())
        ),
        insufficient_credit
    );
    assert_eq!(
        storage_value(&mut fallback_tester, credit_slot(COINBASE)),
        U256::ZERO
    );
    assert_eq!(
        storage_value(&mut fallback_tester, total_credits_slot()),
        insufficient_credit
    );
    assert_native_fee_payment(&mut fallback_tester, &fallback_output, gas_price);
}

#[test]
fn gas_tank_d_reservation_failure_is_p_only_and_atomic() {
    // SYSCOIN: Construct a tx budget that can reserve P but provably cannot
    // reserve D. Half of D remains available for the empty-call payload.
    let requested_remaining = SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST
        + SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST / 2;
    let gas_price = gas_price_for_native_remaining(FALLBACK_GAS_LIMIT, requested_remaining);
    let native_budget = gas_price * FALLBACK_GAS_LIMIT;
    let actual_remaining = native_budget - base_intrinsic_native();
    assert!(actual_remaining >= SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST);
    assert!(
        actual_remaining
            < SYSCOIN_GAS_TANK_PROBE_COMPUTATIONAL_NATIVE_COST
                + SYSCOIN_GAS_TANK_CONDITIONAL_COMPUTATIONAL_NATIVE_COST,
        "test budget must admit P but reject D"
    );

    let base_fee = gas_price;
    let fee_to_prepay = U256::from(gas_price) * U256::from(FALLBACK_GAS_LIMIT);
    let eligible_credit = fee_to_prepay + U256::from(1_000u64);
    let (mut d_failure_tester, d_failure_output) = run_scenario(
        FALLBACK_GAS_LIMIT,
        gas_price,
        base_fee,
        eligible_credit,
        eligible_credit,
    );
    let d_failure_tx = accepted_tx(&d_failure_output);

    let insufficient_credit = fee_to_prepay - U256::ONE;
    let (mut p_only_tester, p_only_output) = run_scenario(
        FALLBACK_GAS_LIMIT,
        gas_price,
        base_fee,
        insufficient_credit,
        insufficient_credit,
    );
    let p_only_tx = accepted_tx(&p_only_output);

    assert_eq!(d_failure_tx.gas_used, p_only_tx.gas_used);
    assert_eq!(
        d_failure_tx.computational_native_used, p_only_tx.computational_native_used,
        "D reservation failure must retain the base+P formula"
    );
    assert_eq!(d_failure_tx.pubdata_used, p_only_tx.pubdata_used);
    assert_eq!(
        d_failure_output.computational_native_used,
        p_only_output.computational_native_used
    );
    assert_eq!(d_failure_output.pubdata_used, p_only_output.pubdata_used);

    assert_eq!(
        storage_value(
            &mut d_failure_tester,
            credit_slot(testing_signer(0).address())
        ),
        eligible_credit,
        "failed D reservation must not debit sender credit"
    );
    assert_eq!(
        storage_value(&mut d_failure_tester, credit_slot(COINBASE)),
        U256::ZERO,
        "failed D reservation must not create operator credit"
    );
    assert_eq!(
        storage_value(&mut d_failure_tester, total_credits_slot()),
        eligible_credit,
        "failed D reservation must not change totalCredits"
    );
    assert_native_fee_payment(&mut d_failure_tester, &d_failure_output, gas_price);

    assert_eq!(
        storage_value(&mut p_only_tester, credit_slot(testing_signer(0).address())),
        insufficient_credit
    );
    assert_eq!(
        storage_value(&mut p_only_tester, total_credits_slot()),
        insufficient_credit
    );
    assert_native_fee_payment(&mut p_only_tester, &p_only_output, gas_price);
}
