use rig::alloy::consensus::TxEip1559;
use rig::alloy::primitives::{address, keccak256, TxKind};
use rig::basic_bootloader::bootloader::transaction_flow::zk::syscoin_edge_da::{
    syscoin_gas_tank_address, syscoin_gas_tank_chain_id,
};
use rig::evm_bytecode::BytecodeBuilder;
use rig::forward_system::run::convert_alloy::{FromAlloy, IntoAlloy};
use rig::ruint::aliases::{B160, B256, U256};
use rig::{alloy, BlockContext, TestingFramework};
use zksync_os_tests_common::zksync_tx::ZKsyncTxEnvelope;

fn credit_slot(account: alloy::primitives::Address) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(account.as_slice());
    // The mapping is at slot zero, so the second ABI word remains zero.
    U256::from_be_bytes(keccak256(preimage).0)
}

fn assert_slot(
    tester: &mut TestingFramework,
    address: &alloy::primitives::Address,
    key: U256,
    expected: U256,
) {
    let actual = tester
        .get_storage_slot(address, key)
        .map(|value| U256::from_be_bytes(value.as_u8_array()))
        .unwrap_or(U256::ZERO);
    assert_eq!(actual, expected);
}

fn simple_transfer(chain_id: u64, recipient: alloy::primitives::Address) -> TxEip1559 {
    l2_call(chain_id, 0, recipient)
}

fn l2_call(chain_id: u64, nonce: u64, recipient: alloy::primitives::Address) -> TxEip1559 {
    TxEip1559 {
        chain_id,
        nonce,
        max_fee_per_gas: 1_500,
        max_priority_fee_per_gas: 500,
        gas_limit: 100_000,
        to: TxKind::Call(recipient),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Default::default(),
    }
}

fn run_edge_tank_payment(coinbase_credit: U256) {
    let edge_chain_id = syscoin_gas_tank_chain_id();
    assert_ne!(edge_chain_id, 0, "test build must configure the edge chain");

    let coinbase = address!("1000000000000000000000000000000000000001");
    let recipient = address!("2000000000000000000000000000000000000002");
    let block_context = BlockContext {
        eip1559_basefee: U256::from(1_000u64),
        native_price: U256::ONE,
        pubdata_price: U256::ONE,
        coinbase: B160::from_alloy(coinbase),
        ..Default::default()
    };
    let mut tester = TestingFramework::new()
        .with_chain_id(edge_chain_id)
        .with_block_context(block_context);
    let signer = tester.prefunded_random_signer();

    let tank = syscoin_gas_tank_address().into_alloy();
    let sender_credit_key = credit_slot(signer.address());
    let coinbase_credit_key = credit_slot(coinbase);
    let total_credits_key = U256::ONE;
    let sender_credit = U256::from(500_000_000_000u64);
    let total_credits = sender_credit + coinbase_credit;
    tester
        .set_storage_slot(tank, sender_credit_key, B256::from(sender_credit))
        .set_storage_slot(tank, total_credits_key, B256::from(total_credits));
    if !coinbase_credit.is_zero() {
        tester.set_storage_slot(tank, coinbase_credit_key, B256::from(coinbase_credit));
    }

    let sender_native_before = tester.get_balance(&signer.address());
    let coinbase_native_before = tester.get_balance(&coinbase);
    let output = tester.execute_block(vec![ZKsyncTxEnvelope::from_eth_tx(
        simple_transfer(edge_chain_id, recipient),
        signer.clone(),
    )]);
    let result = output.tx_results[0]
        .as_ref()
        .expect("edge transaction must be processed");
    assert!(result.is_success(), "edge transaction failed: {result:?}");

    let effective_gas_price = U256::from(1_500u64);
    let prepaid = effective_gas_price * U256::from(100_000u64);
    let refund = effective_gas_price * U256::from(100_000u64 - result.gas_used);
    let operator_tip = U256::from(500u64) * U256::from(result.gas_used);
    let burned = prepaid - refund - operator_tip;
    assert_slot(
        &mut tester,
        &tank,
        sender_credit_key,
        sender_credit - prepaid + refund,
    );
    assert_slot(
        &mut tester,
        &tank,
        coinbase_credit_key,
        coinbase_credit + operator_tip,
    );
    assert_slot(
        &mut tester,
        &tank,
        total_credits_key,
        total_credits - burned,
    );
    assert_eq!(
        tester.get_balance(&signer.address()),
        sender_native_before,
        "tank-paid fee must not debit the sender's native balance",
    );
    assert_eq!(
        tester.get_balance(&coinbase),
        coinbase_native_before,
        "tank-paid operator tip must remain in the tank ledger",
    );
}

#[test]
fn edge_chain_tank_payment_covers_new_coinbase_credit_slot() {
    // SYSCOIN: cover a new operator slot when sender and total were already
    // persisted before the batch; the same-batch test below covers all-new
    // slot pricing.
    run_edge_tank_payment(U256::ZERO);
}

#[test]
fn edge_chain_tank_payment_with_existing_coinbase_credit_slot() {
    run_edge_tank_payment(U256::from(7_000_000_000u64));
}

#[test]
fn edge_chain_tank_payment_covers_slots_created_earlier_in_the_same_batch() {
    let edge_chain_id = syscoin_gas_tank_chain_id();
    assert_ne!(edge_chain_id, 0, "test build must configure the edge chain");

    let coinbase = address!("1000000000000000000000000000000000000001");
    let recipient = address!("2000000000000000000000000000000000000002");
    let block_context = BlockContext {
        eip1559_basefee: U256::from(1_000u64),
        native_price: U256::ONE,
        pubdata_price: U256::ONE,
        coinbase: B160::from_alloy(coinbase),
        ..Default::default()
    };
    let mut tester = TestingFramework::new()
        .with_chain_id(edge_chain_id)
        .with_block_context(block_context);
    let signer = tester.prefunded_random_signer();

    let tank = syscoin_gas_tank_address().into_alloy();
    let sender_credit_key = credit_slot(signer.address());
    let coinbase_credit_key = credit_slot(coinbase);
    let total_credits_key = U256::ONE;
    let sender_credit = U256::from(500_000_000_000u64);

    // SYSCOIN: transaction zero executes real EVM SSTOREs at the tank address;
    // no storage fixture creates these slots. The flat-storage cache therefore
    // retains `is_new_slot` when transaction one reads and rewrites them.
    let tank_deposit_runtime = BytecodeBuilder::new()
        .push_bytes(&sender_credit.to_be_bytes::<32>())
        .push_bytes(&sender_credit_key.to_be_bytes::<32>())
        .sstore()
        .push_bytes(&sender_credit.to_be_bytes::<32>())
        .push_u8(1)
        .sstore()
        .stop()
        .finish();
    tester.set_evm_contract(tank, &tank_deposit_runtime);
    assert!(tester.get_storage_slot(&tank, sender_credit_key).is_none());
    assert!(tester
        .get_storage_slot(&tank, coinbase_credit_key)
        .is_none());
    assert!(tester.get_storage_slot(&tank, total_credits_key).is_none());

    let sender_native_before = tester.get_balance(&signer.address());
    let output = tester.execute_block(vec![
        ZKsyncTxEnvelope::from_eth_tx(l2_call(edge_chain_id, 0, tank), signer.clone()),
        ZKsyncTxEnvelope::from_eth_tx(l2_call(edge_chain_id, 1, recipient), signer.clone()),
    ]);
    let deposit_result = output.tx_results[0]
        .as_ref()
        .expect("same-batch deposit transaction must be processed");
    assert!(
        deposit_result.is_success(),
        "same-batch deposit transaction failed: {deposit_result:?}"
    );
    let payment_result = output.tx_results[1]
        .as_ref()
        .expect("same-batch tank payment must be processed");
    assert!(
        payment_result.is_success(),
        "same-batch tank payment failed: {payment_result:?}"
    );

    let effective_gas_price = U256::from(1_500u64);
    let prepaid = effective_gas_price * U256::from(100_000u64);
    let refund = effective_gas_price * U256::from(100_000u64 - payment_result.gas_used);
    let operator_tip = U256::from(500u64) * U256::from(payment_result.gas_used);
    let burned = prepaid - refund - operator_tip;
    assert_slot(
        &mut tester,
        &tank,
        sender_credit_key,
        sender_credit - prepaid + refund,
    );
    assert_slot(&mut tester, &tank, coinbase_credit_key, operator_tip);
    assert_slot(
        &mut tester,
        &tank,
        total_credits_key,
        sender_credit - burned,
    );
    assert!(
        tester.get_balance(&signer.address()) < sender_native_before,
        "the first transaction must use native fallback before it creates credit",
    );
}

fn run_edge_insufficient_tank_credit_fallback(sender_credit: U256) {
    let edge_chain_id = syscoin_gas_tank_chain_id();
    assert_ne!(edge_chain_id, 0, "test build must configure the edge chain");

    let coinbase = address!("1000000000000000000000000000000000000001");
    let recipient = address!("2000000000000000000000000000000000000002");
    let block_context = BlockContext {
        eip1559_basefee: U256::from(1_000u64),
        native_price: U256::ONE,
        pubdata_price: U256::ONE,
        coinbase: B160::from_alloy(coinbase),
        ..Default::default()
    };
    let mut tester = TestingFramework::new()
        .with_chain_id(edge_chain_id)
        .with_block_context(block_context);
    let signer = tester.prefunded_random_signer();

    let tank = syscoin_gas_tank_address().into_alloy();
    let sender_credit_key = credit_slot(signer.address());
    let coinbase_credit_key = credit_slot(coinbase);
    let total_credits_key = U256::ONE;
    let coinbase_credit = U256::from(7_000_000_000u64);
    let total_credits = sender_credit + coinbase_credit;
    tester
        .set_storage_slot(tank, coinbase_credit_key, B256::from(coinbase_credit))
        .set_storage_slot(tank, total_credits_key, B256::from(total_credits));
    if !sender_credit.is_zero() {
        tester.set_storage_slot(tank, sender_credit_key, B256::from(sender_credit));
    }

    let sender_native_before = tester.get_balance(&signer.address());
    let coinbase_native_before = tester.get_balance(&coinbase);
    let output = tester.execute_block(vec![ZKsyncTxEnvelope::from_eth_tx(
        simple_transfer(edge_chain_id, recipient),
        signer.clone(),
    )]);
    let result = output.tx_results[0]
        .as_ref()
        .expect("edge fallback transaction must be processed");
    assert!(
        result.is_success(),
        "edge fallback transaction failed: {result:?}"
    );

    assert_slot(&mut tester, &tank, sender_credit_key, sender_credit);
    assert_slot(&mut tester, &tank, coinbase_credit_key, coinbase_credit);
    assert_slot(&mut tester, &tank, total_credits_key, total_credits);
    assert!(
        tester.get_balance(&signer.address()) < sender_native_before,
        "insufficient tank credit must fall back to the native sender balance",
    );
    assert!(
        tester.get_balance(&coinbase) > coinbase_native_before,
        "native fallback must pay the operator's native balance",
    );
}

#[test]
fn edge_chain_absent_tank_credit_falls_back_to_native() {
    // SYSCOIN: an account that never deposited exercises the most expensive
    // insufficient-credit lookup branch.
    run_edge_insufficient_tank_credit_fallback(U256::ZERO);
}

#[test]
fn edge_chain_existing_insufficient_tank_credit_falls_back_to_native() {
    run_edge_insufficient_tank_credit_fallback(U256::from(149_999_999u64));
}

#[test]
fn non_edge_chain_ignores_populated_gas_tank_storage() {
    let edge_chain_id = syscoin_gas_tank_chain_id();
    assert_ne!(edge_chain_id, 0, "test build must configure the edge chain");
    let gateway_chain_id = if edge_chain_id == u64::MAX {
        edge_chain_id - 1
    } else {
        edge_chain_id + 1
    };

    let coinbase = address!("1000000000000000000000000000000000000001");
    let recipient = address!("2000000000000000000000000000000000000002");
    let block_context = BlockContext {
        eip1559_basefee: U256::from(1_000u64),
        native_price: U256::ONE,
        pubdata_price: U256::ONE,
        coinbase: B160::from_alloy(coinbase),
        ..Default::default()
    };
    let mut tester = TestingFramework::new()
        .with_chain_id(gateway_chain_id)
        .with_block_context(block_context);
    let signer = tester.prefunded_random_signer();

    let tank = syscoin_gas_tank_address().into_alloy();
    assert_ne!(tank, alloy::primitives::Address::ZERO);
    let sender_credit_key = credit_slot(signer.address());
    let coinbase_credit_key = credit_slot(coinbase);
    let total_credits_key = U256::ONE;
    let sender_credit = U256::from(500_000_000_000u64);
    let coinbase_credit = U256::from(7_000_000_000u64);
    let total_credits = sender_credit + coinbase_credit;

    // SYSCOIN: populate a fully plausible tank ledger at the compiled edge
    // address. A non-edge execution must neither read it for fee selection nor
    // mutate sender/operator/total slots during settlement.
    tester
        .set_storage_slot(tank, sender_credit_key, B256::from(sender_credit))
        .set_storage_slot(tank, coinbase_credit_key, B256::from(coinbase_credit))
        .set_storage_slot(tank, total_credits_key, B256::from(total_credits));

    let sender_native_before = tester.get_balance(&signer.address());
    let coinbase_native_before = tester.get_balance(&coinbase);
    let tx = simple_transfer(gateway_chain_id, recipient);
    let output = tester.execute_block(vec![ZKsyncTxEnvelope::from_eth_tx(tx, signer.clone())]);
    let result = output.tx_results[0]
        .as_ref()
        .expect("Gateway transaction must be processed");
    assert!(
        result.is_success(),
        "Gateway transaction failed: {result:?}"
    );

    assert_slot(&mut tester, &tank, sender_credit_key, sender_credit);
    assert_slot(&mut tester, &tank, coinbase_credit_key, coinbase_credit);
    assert_slot(&mut tester, &tank, total_credits_key, total_credits);
    assert!(
        tester.get_balance(&signer.address()) < sender_native_before,
        "non-edge fee must debit the sender's native balance"
    );
    assert!(
        tester.get_balance(&coinbase) > coinbase_native_before,
        "non-edge fee must credit the operator's native balance"
    );
}
