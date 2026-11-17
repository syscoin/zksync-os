use zk_ee::{system::AccountDataRequest, utils::UsizeAlignedByteBox};

use super::*;
use crate::bootloader::{
    block_flow::tx_loop::TxLoopOp, transaction_flow::zk::ZkTransactionFlowOnlyEOA,
};
// SYSCOIN: authorized Gateway commits bind exactly one message from the baked relay emitter.
use crate::bootloader::transaction_flow::zk::syscoin_edge_da::{
    syscoin_compact_edge_da_enabled_on_chain, syscoin_compact_edge_da_relay_emitter,
};
use zk_ee::common_structs::SyscoinEdgeDaRelayMessage;
use zk_ee::memory::stack_trait::Stack;
use zk_ee::system::{IOTeardown, Resource};
use zk_ee::utils::Bytes32;

// SYSCOIN: Keep the cross-block arithmetic in one testable, overflow-safe helper; the caller
// compares the returned batch total with the consensus 32-opening limit before committing a tx.
fn next_syscoin_edge_da_ref_counts(
    prior_blocks: u32,
    current_block: u32,
    current_tx: u32,
) -> Result<(u32, u32), zk_ee::system::errors::internal::InternalError> {
    let next_block = current_block
        .checked_add(current_tx)
        .ok_or_else(|| internal_error!("Syscoin edge DA ref count overflow"))?;
    let next_batch = prior_blocks
        .checked_add(next_block)
        .ok_or_else(|| internal_error!("Syscoin edge DA ref count overflow"))?;
    Ok((next_block, next_batch))
}

// SYSCOIN: turn strict raw-message analysis into the one optional hash/count that may survive
// transaction rollback. Unsupported call shapes must not silently discard authentic relay messages.
fn validated_syscoin_edge_da_ref(
    is_authorized_success: bool,
    relay_message: Option<SyscoinEdgeDaRelayMessage>,
) -> Result<Option<(u32, Bytes32)>, InvalidTransaction> {
    if !is_authorized_success {
        return match relay_message {
            None | Some(SyscoinEdgeDaRelayMessage::Missing) => Ok(None),
            Some(_) => Err(InvalidTransaction::InvalidStructure),
        };
    }
    match relay_message {
        Some(SyscoinEdgeDaRelayMessage::Valid {
            ref_count,
            ref_hash,
        }) => Ok(Some((ref_count, ref_hash))),
        Some(
            SyscoinEdgeDaRelayMessage::Missing
            | SyscoinEdgeDaRelayMessage::Malformed
            | SyscoinEdgeDaRelayMessage::Duplicate,
        )
        | None => Err(InvalidTransaction::InvalidStructure),
    }
}

// SYSCOIN: a transaction larger than the whole batch allowance can never succeed after sealing;
// distinguish that invalid shape from aggregate overflow that is retryable in a fresh batch.
fn syscoin_edge_da_ref_limit_error(
    refs_in_tx: u32,
    refs_in_batch: u32,
) -> Option<InvalidTransaction> {
    if refs_in_tx > zk_ee::common_structs::logs_storage::SYSCOIN_DA_MAX_REFS_PER_BATCH {
        Some(InvalidTransaction::InvalidStructure)
    } else if refs_in_batch > zk_ee::common_structs::logs_storage::SYSCOIN_DA_MAX_REFS_PER_BATCH {
        Some(InvalidTransaction::SyscoinEdgeDaRefsLimitReached)
    } else {
        None
    }
}

impl<
        S: EthereumLikeTypes<Metadata = zk_ee::system::metadata::zk_metadata::ZkMetadata>,
        BlockEA: TxHashesAccumulator,
        BatchEA: TxHashesAccumulator,
    > TxLoopOp<S> for ZKHeaderStructureTxLoop<BlockEA, BatchEA>
where
    S::IO: IOSubsystemExt + IOTeardown<S::IOTypes>,
    S::Metadata: ZkSpecificMetadata,
{
    type BlockDataKeeper = ZKBasicBlockDataKeeper<BlockEA, S::Allocator>;
    // we write only enforced tx hashes to the batch data, so it can be anything that implements tx hashes accumulator
    type BatchDataKeeper = BatchEA;

    fn loop_op<'a, Config: BasicBootloaderExecutionConfig>(
        system: &mut System<S>,
        system_functions: &mut HooksStorage<S, S::Allocator>,
        mut memories: RunnerMemoryBuffers<'a>,
        block_data: &mut Self::BlockDataKeeper,
        batch_data: &mut Self::BatchDataKeeper,
        result_keeper: &mut impl ResultKeeperExt<EthereumIOTypesConfig>,
        tracer: &mut impl Tracer<S>,
        validator: &mut impl TxValidator<S>,
    ) -> Result<(), BootloaderSubsystemError> {
        cycle_marker::start!("run_tx_loop");

        let mut is_first_tx = true;
        // Service blocks are blocks that only contain service transactions,
        // optionally prefixed by a single upgrade tx.
        let mut is_service_block = false;
        let mut can_start_service_block_after_upgrade = false;

        // TODO use preallocated data buffer?

        // now we can run every transaction
        while let Some(r) = {
            let allocator = system.get_allocator();
            system.try_begin_next_tx(move |tx_length_in_bytes| {
                UsizeAlignedByteBox::preallocated_in(tx_length_in_bytes, allocator)
            })
        } {
            match r {
                Err(err) => {
                    system_log!(
                        system,
                        "Failure while reading tx from oracle: decoding error = {err:?}\n",
                    );
                    result_keeper.tx_processed(Err(InvalidTransaction::InvalidEncoding));
                }
                Ok((_next_tx_len_bytes, initial_calldata_buffer)) => {
                    // warm up the coinbase formally
                    {
                        let mut inf_resources = S::Resources::FORMAL_INFINITE;
                        system
                            .io
                            .read_account_properties(
                                ExecutionEnvironmentType::NoEE,
                                &mut inf_resources,
                                &system.get_coinbase(),
                                AccountDataRequest::empty(),
                            )
                            .expect("must heat coinbase");
                    }

                    system_log!(system, "====================================\n",);
                    system_log!(system, "TX execution begins\n");

                    tracer.begin_tx(initial_calldata_buffer.as_slice());

                    // Take a snapshot in case we need to invalidate the
                    // transaction to seal the block.
                    // This can happen if any of the block limits (native, gas, pubdata
                    // logs) is reached by the current transaction.
                    let pre_tx_rollback_handle = system.start_global_frame()?;

                    // We will give the full buffer here, and internally we will use parts of it to give forward to EEs
                    cycle_marker::start!("process_transaction");

                    // TODO: consider actually using block_data here
                    let mut nop_keeper = NopTransactionDataKeeper;

                    let tx_result =
                        BasicBootloader::<S, ZkTransactionFlowOnlyEOA<S>>::process_transaction::<
                            Config,
                        >(
                            initial_calldata_buffer,
                            system,
                            system_functions,
                            memories.reborrow(),
                            is_first_tx,
                            &mut nop_keeper,
                            tracer,
                            validator,
                        );

                    cycle_marker::end!("process_transaction");

                    tracer.finish_tx();

                    if system
                        .io
                        .transaction_cache_memory_limit_hit_for_current_tx()
                    {
                        system_log!(
                            system,
                            "Tx exhausted its preimage-cache memory budget (OON)\n",
                        );
                    }

                    // Raw preimages are retained for the whole block and are
                    // intentionally not part of frame rollback. If this tx
                    // encountered their hard memory cap, treat it like any
                    // other block limit before fees or tx effects can commit.
                    if system.io.block_scoped_cache_limit_hit_for_current_tx() {
                        system_log!(system, "Tx reached block-scoped cache limit\n",);
                        system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                        result_keeper
                            .tx_processed(Err(InvalidTransaction::BlockNativeLimitReached));
                        continue;
                    }

                    match tx_result {
                        Err(TxError::Internal(err)) => {
                            system_log!(system, "Tx execution result: Internal error = {err:?}\n",);
                            // Finish the frame opened before processing the tx
                            system.finish_global_frame(None)?; // TODO should we use pre_tx_rollback_handle here?
                            return Err(err);
                        }
                        Err(TxError::Validation(err)) => {
                            system_log!(
                                system,
                                "Tx execution result: Validation error = {err:?}\n",
                            );
                            // Revert to state before transaction
                            system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                            result_keeper.tx_processed(Err(err));
                        }
                        Ok(tx_processing_result) => {
                            system_log!(
                                system,
                                "Tx execution result = {:?}\n",
                                &tx_processing_result,
                            );

                            // Check for service block invariants
                            let starts_service_block = check_for_service_block_invariants(
                                is_service_block,
                                is_first_tx,
                                tx_processing_result.is_service_tx,
                                can_start_service_block_after_upgrade,
                            )?;

                            // Do not update the accumulators yet, we may need to revert the transaction
                            let next_block_gas_used =
                                block_data.block_gas_used + tx_processing_result.gas_used;
                            let next_block_pubdata_used =
                                block_data.block_pubdata_used + tx_processing_result.pubdata_used;
                            let block_logs_used = system.io.logs_len();
                            let next_block_blob_gas_used =
                                block_data.block_blob_gas_used + tx_processing_result.blob_gas_used;
                            let tx_status = matches!(
                                &tx_processing_result.result,
                                ExecutionResult::Success { .. }
                            );
                            // SYSCOIN: Analyze the baked relay's raw message set while the current
                            // transaction frame can still be rolled back.
                            let is_authorized_syscoin_edge_da_commit =
                                tx_status && tx_processing_result.collects_syscoin_edge_da_refs;
                            let syscoin_edge_da_relay_message = if tx_status
                                && syscoin_compact_edge_da_enabled_on_chain(system.get_chain_id())
                            {
                                let canonical_relay_emitter =
                                    syscoin_compact_edge_da_relay_emitter();
                                Some(system.io.syscoin_edge_da_relay_message_for_tx_number(
                                    block_data.current_transaction_number,
                                    &canonical_relay_emitter,
                                ))
                            } else {
                                None
                            };
                            let (syscoin_edge_da_ref, syscoin_edge_da_structure_error) =
                                match validated_syscoin_edge_da_ref(
                                    is_authorized_syscoin_edge_da_commit,
                                    syscoin_edge_da_relay_message,
                                ) {
                                    Ok(edge_ref) => (edge_ref, None),
                                    Err(err) => (None, Some(err)),
                                };
                            let syscoin_edge_da_refs_in_tx = match syscoin_edge_da_ref {
                                Some((ref_count, _)) => ref_count,
                                None => 0,
                            };
                            let (
                                next_syscoin_edge_da_refs_in_block,
                                next_syscoin_edge_da_refs_in_batch,
                            ) = next_syscoin_edge_da_ref_counts(
                                batch_data.syscoin_edge_da_ref_count(),
                                block_data.syscoin_compact_edge_da_ref_count,
                                syscoin_edge_da_refs_in_tx,
                            )?;
                            let receipt_hash = compute_receipt_hash(
                                tx_processing_result.tx_type,
                                &tx_status,
                                &next_block_gas_used,
                                system.io.events_in_this_tx_iterator(),
                            );
                            let computational_native_used =
                                tx_processing_result.computational_native_used;
                            let next_block_computational_native_used = block_data
                                .block_computational_native_used
                                + computational_native_used;

                            // Check if the transaction made the block reach any of the limits
                            // for gas, native, pubdata or logs.
                            if let Some(err) = syscoin_edge_da_structure_error {
                                // SYSCOIN: Invalid or unsupported relay emissions must roll back
                                // the child commit as well as its DA count/hash.
                                system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                                result_keeper.tx_processed(Err(err));
                            } else if let Some(limit_error) = syscoin_edge_da_ref_limit_error(
                                syscoin_edge_da_refs_in_tx,
                                next_syscoin_edge_da_refs_in_batch,
                            ) {
                                // SYSCOIN: aggregate overflow seals/retries, while a single
                                // intrinsically oversized commit is invalid even in an empty batch.
                                system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                                result_keeper.tx_processed(Err(limit_error));
                            } else if let Err(err) = check_for_block_limits(
                                system,
                                next_block_gas_used,
                                next_block_computational_native_used,
                                next_block_pubdata_used,
                                block_logs_used,
                                next_block_blob_gas_used,
                            ) {
                                // Revert to state before transaction
                                system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                                result_keeper.tx_processed(Err(err));
                            } else {
                                // Now update the accumulators
                                block_data.block_gas_used = next_block_gas_used;
                                block_data.block_computational_native_used =
                                    next_block_computational_native_used;
                                block_data.block_pubdata_used = next_block_pubdata_used;
                                block_data.block_blob_gas_used = next_block_blob_gas_used;
                                // SYSCOIN: Persist only the count from a commit transaction that
                                // survived all rollback-capable structure and capacity checks.
                                block_data.syscoin_compact_edge_da_ref_count =
                                    next_syscoin_edge_da_refs_in_block;

                                if starts_service_block {
                                    is_service_block = true;
                                    can_start_service_block_after_upgrade = false;
                                } else if is_first_tx && tx_processing_result.is_upgrade_tx {
                                    can_start_service_block_after_upgrade = true;
                                } else if can_start_service_block_after_upgrade
                                    && !tx_processing_result.is_service_tx
                                {
                                    can_start_service_block_after_upgrade = false;
                                }

                                is_first_tx = false;

                                // Finish the frame opened before processing the tx
                                system.finish_global_frame(None)?;

                                let (status, output, contract_address) =
                                    match tx_processing_result.result {
                                        ExecutionResult::Success { output } => match output {
                                            ExecutionOutput::Call(output) => (true, output, None),
                                            ExecutionOutput::Create(output, contract_address) => {
                                                (true, output, Some(contract_address))
                                            }
                                        },
                                        ExecutionResult::Revert { output } => (false, output, None),
                                    };

                                block_data
                                    .transaction_hashes
                                    .push(tx_processing_result.tx_hash);
                                block_data.receipt_hashes.push(receipt_hash);
                                if tx_processing_result.is_priority_tx {
                                    block_data
                                        .enforced_transaction_hashes_accumulator
                                        .add_tx_hash(&tx_processing_result.tx_hash);
                                    // In the multiblock proving path the per-block enforced-tx
                                    // accumulator may be a no-op, but batch_data still collects
                                    // these hashes for the batch-level priority hash/count.
                                    batch_data.add_tx_hash(&tx_processing_result.tx_hash);
                                }
                                if tx_processing_result.is_upgrade_tx {
                                    block_data
                                        .upgrade_tx_recorder
                                        .add_upgrade_tx_hash(&tx_processing_result.tx_hash);
                                }
                                if is_authorized_syscoin_edge_da_commit {
                                    // SYSCOIN: retain the already validated hash, never a tx number
                                    // that would require permissive post-op log reparsing.
                                    let (_, ref_hash) = syscoin_edge_da_ref.expect(
                                        "authorized accepted Edge-DA commit must have a validated ref",
                                    );
                                    block_data
                                        .syscoin_compact_edge_da_ref_hashes
                                        .try_push(ref_hash)
                                        .map_err(|_| {
                                            internal_error!("too many Syscoin edge DA ref hashes")
                                        })?;
                                }
                                block_data.current_transaction_number = block_data
                                    .current_transaction_number
                                    .checked_add(1)
                                    .ok_or_else(|| {
                                        internal_error!("too many transactions in block")
                                    })?;

                                result_keeper.tx_processed(Ok(TxProcessingOutput {
                                    status,
                                    output: &output,
                                    contract_address,
                                    gas_used: tx_processing_result.gas_used,
                                    gas_refunded: tx_processing_result.gas_refunded,
                                    computational_native_used,
                                    native_used: tx_processing_result.native_used,
                                    pubdata_used: tx_processing_result.pubdata_used,
                                }));

                                // Only bump tx number when tx is successful
                                system.finish_valid_tx()?;
                            }
                        }
                    }

                    system_log!(system, "TX execution ends\n");
                    system_log!(system, "====================================\n");
                }
            }
        }

        cycle_marker::end!("run_tx_loop");

        Ok(())
    }
}

#[cfg(test)]
// SYSCOIN: Regression coverage for compact-ref admission and cross-block cap classification.
mod syscoin_tests {
    use super::{
        next_syscoin_edge_da_ref_counts, syscoin_edge_da_ref_limit_error,
        validated_syscoin_edge_da_ref,
    };
    use crate::bootloader::errors::InvalidTransaction;
    use zk_ee::common_structs::logs_storage::{
        SyscoinEdgeDaRelayMessage, SYSCOIN_DA_MAX_REFS_PER_BATCH,
    };
    use zk_ee::utils::Bytes32;

    #[test]
    fn gateway_refs_exact_limit_across_blocks_is_accepted() {
        let (_, batch_total) = next_syscoin_edge_da_ref_counts(20, 0, 12).unwrap();
        assert_eq!(batch_total, SYSCOIN_DA_MAX_REFS_PER_BATCH);
    }

    #[test]
    fn gateway_refs_twenty_plus_thirteen_classifies_for_seal_and_retry() {
        let (_, batch_total) = next_syscoin_edge_da_ref_counts(20, 0, 13).unwrap();
        assert!(matches!(
            syscoin_edge_da_ref_limit_error(13, batch_total),
            Some(InvalidTransaction::SyscoinEdgeDaRefsLimitReached)
        ));
    }

    #[test]
    fn gateway_single_transaction_above_limit_is_unrecoverably_invalid() {
        let (_, batch_total) = next_syscoin_edge_da_ref_counts(0, 0, 33).unwrap();
        assert!(matches!(
            syscoin_edge_da_ref_limit_error(33, batch_total),
            Some(InvalidTransaction::InvalidStructure)
        ));
    }

    #[test]
    fn successful_authorized_gateway_commit_requires_exactly_one_valid_relay_message() {
        for invalid_message in [
            SyscoinEdgeDaRelayMessage::Missing,
            SyscoinEdgeDaRelayMessage::Malformed,
            SyscoinEdgeDaRelayMessage::Duplicate,
        ] {
            assert!(matches!(
                validated_syscoin_edge_da_ref(true, Some(invalid_message)),
                Err(InvalidTransaction::InvalidStructure)
            ));
        }

        let ref_hash = Bytes32::from_array([0x81; 32]);
        assert_eq!(
            validated_syscoin_edge_da_ref(
                true,
                Some(SyscoinEdgeDaRelayMessage::Valid {
                    ref_count: 2,
                    ref_hash,
                })
            )
            .unwrap(),
            Some((2, ref_hash))
        );
    }

    #[test]
    fn unsupported_gateway_call_cannot_discard_canonical_relay_messages() {
        for relay_message in [
            SyscoinEdgeDaRelayMessage::Valid {
                ref_count: 1,
                ref_hash: Bytes32::from_array([0x81; 32]),
            },
            SyscoinEdgeDaRelayMessage::Malformed,
            SyscoinEdgeDaRelayMessage::Duplicate,
        ] {
            assert!(matches!(
                validated_syscoin_edge_da_ref(false, Some(relay_message)),
                Err(InvalidTransaction::InvalidStructure)
            ));
        }
    }

    #[test]
    fn unrelated_successful_transaction_does_not_require_a_relay_message() {
        assert_eq!(validated_syscoin_edge_da_ref(false, None).unwrap(), None);
        assert_eq!(
            validated_syscoin_edge_da_ref(false, Some(SyscoinEdgeDaRelayMessage::Missing)).unwrap(),
            None
        );
    }
}
