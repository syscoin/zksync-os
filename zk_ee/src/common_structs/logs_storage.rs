//! Storage of L2->L1 logs.
//! There are two kinds of such logs:
//! - user messages (sent via l1 messenger system hook).
//! - l1 -> l2 txs logs, to prove execution result on l1.
use super::history_list::HistoryList;
use super::merkle_tree::merkle_root_in_place;
use crate::internal_error;
use crate::system::errors::internal::InternalError;
use crate::system::IOResultKeeper;
use crate::utils::write_bytes::WriteBytes;
use crate::{
    memory::stack_trait::StackFactory,
    system::errors::system::SystemError,
    types_config::{EthereumIOTypesConfig, SystemIOTypesConfig},
    utils::{Bytes32, UsizeAlignedByteBox},
};
use alloc::alloc::Global;
use arrayvec::ArrayVec;
use core::alloc::Allocator;
use crypto::MiniDigest;
use ruint::aliases::B160;
use ruint::aliases::U256;

pub const L2_TO_L1_LOG_SERIALIZE_SIZE: usize = 88;
// Taken from the size of the Merkle tree.
pub const MAX_NUMBER_OF_LOGS: u64 = 16_384;
// SYSCOIN: compact RelayedSLDAValidator message version for edge DA refs.
const SYSCOIN_RELAYED_EDGE_DA_VALIDATOR_VERSION: u8 = 1;
const SYSCOIN_EDGE_DA_REFS_DOMAIN: &[u8] = b"SYSCOIN_EDGE_DA_REFS_V1";
// SYSCOIN: One Gateway batch may forward at most the same 32 Bitcoin-DA openings accepted
// by a direct Syscoin DA batch; this is enforced per message and cumulatively by the guest.
pub const SYSCOIN_DA_MAX_REFS_PER_BATCH: u32 = 32;
const ABI_WORD: usize = 32;
const SYSCOIN_EDGE_DA_REF_HEAD_BYTES: usize = ABI_WORD * 5;

/// SYSCOIN: fail-closed classification of the canonical relay's raw message set for one
/// authorized Gateway commit transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscoinEdgeDaRelayMessage {
    /// No message was emitted by the baked relay address.
    Missing,
    /// Exactly one raw relay message was present, but its envelope or commitment was invalid.
    Malformed,
    /// More than one raw message was emitted by the baked relay, regardless of message validity.
    Duplicate,
    /// Exactly one canonical non-empty message was emitted by the baked relay.
    Valid { ref_count: u32, ref_hash: Bytes32 },
}

/// SYSCOIN: extend the proven ordered Edge-DA root with already validated relay-message hashes.
pub fn apply_syscoin_edge_da_ref_hashes(root: &mut Bytes32, ref_hashes: &[Bytes32]) {
    for ref_hash in ref_hashes {
        let mut hasher = crypto::sha3::Keccak256::new();
        hasher.update(root.as_u8_ref());
        hasher.update(ref_hash.as_u8_ref());
        *root = hasher.finalize().into();
    }
}

/// SYSCOIN: construct a fresh ordered Edge-DA root from hashes validated while each transaction
/// was still rollback-capable.
pub fn syscoin_edge_da_refs_root_from_hashes(ref_hashes: &[Bytes32]) -> Bytes32 {
    let mut root = Bytes32::ZERO;
    apply_syscoin_edge_da_ref_hashes(&mut root, ref_hashes);
    root
}

/// Height of the L2->L1 logs Merkle tree (capacity `2^14 == 16_384` leaves).
pub const L2_TO_L1_LOG_TREE_HEIGHT: usize = 14;

/// Empty-subtree hashes for the L2->L1 logs tree, where entry `i` is the root
/// of an empty subtree of height `i`. The empty leaf is `keccak256([0; 88])`
/// (the hash of a zeroed log), and each level doubles up:
/// `entry[i] = keccak256(entry[i - 1] || entry[i - 1])`.
///
/// These are the input expected by
/// [`merkle_root_in_place`](crate::common_structs::merkle_root_in_place) for the
/// logs tree; the recurrence is checked against this table in the `merkle_tree`
/// unit tests.
pub const L2_TO_L1_LOG_EMPTY_SUBTREE_HASHES: [[u8; 32]; L2_TO_L1_LOG_TREE_HEIGHT + 1] = [
    [
        0x72, 0xab, 0xee, 0x45, 0xb5, 0x9e, 0x34, 0x4a, 0xf8, 0xa6, 0xe5, 0x20, 0x24, 0x1c, 0x47,
        0x44, 0xaf, 0xf2, 0x6e, 0xd4, 0x11, 0xf4, 0xc4, 0xb0, 0x0f, 0x8a, 0xf0, 0x9a, 0xda, 0xda,
        0x43, 0xba,
    ],
    [
        0xc3, 0xd0, 0x3e, 0xeb, 0xfd, 0x83, 0x04, 0x99, 0x91, 0xea, 0x3d, 0x3e, 0x35, 0x8b, 0x67,
        0x12, 0xe7, 0xaa, 0x2e, 0x2e, 0x63, 0xdc, 0x2d, 0x4b, 0x43, 0x89, 0x87, 0xce, 0xc2, 0x8a,
        0xc8, 0xd0,
    ],
    [
        0xe3, 0x69, 0x7c, 0x7f, 0x33, 0xc3, 0x1a, 0x9b, 0x0f, 0x0a, 0xeb, 0x85, 0x42, 0x28, 0x7d,
        0x0d, 0x21, 0xe8, 0xc4, 0xcf, 0x82, 0x16, 0x3d, 0x0c, 0x44, 0xc7, 0xa9, 0x8a, 0xa1, 0x1a,
        0xa1, 0x11,
    ],
    [
        0x19, 0x9c, 0xc5, 0x81, 0x25, 0x43, 0xdd, 0xce, 0xed, 0xdd, 0x0f, 0xc8, 0x28, 0x07, 0x64,
        0x6a, 0x48, 0x99, 0x44, 0x42, 0x40, 0xdb, 0x2c, 0x0d, 0x2f, 0x20, 0xc3, 0xcc, 0xeb, 0x5f,
        0x51, 0xfa,
    ],
    [
        0xe4, 0x73, 0x3f, 0x28, 0x1f, 0x18, 0xba, 0x3e, 0xa8, 0x77, 0x5d, 0xd6, 0x2d, 0x2f, 0xcd,
        0x84, 0x01, 0x1c, 0x8c, 0x93, 0x8f, 0x16, 0xea, 0x57, 0x90, 0xfd, 0x29, 0xa0, 0x3b, 0xf8,
        0xdb, 0x89,
    ],
    [
        0x17, 0x98, 0xa1, 0xfd, 0x9c, 0x8f, 0xbb, 0x81, 0x8c, 0x98, 0xcf, 0xf1, 0x90, 0xda, 0xa7,
        0xcc, 0x10, 0xb6, 0xe5, 0xac, 0x97, 0x16, 0xb4, 0xa2, 0x64, 0x9f, 0x7c, 0x2e, 0xbc, 0xef,
        0x22, 0x72,
    ],
    [
        0x66, 0xd7, 0xc5, 0x98, 0x3a, 0xfe, 0x44, 0xcf, 0x15, 0xea, 0x8c, 0xf5, 0x65, 0xb3, 0x4c,
        0x6c, 0x31, 0xff, 0x0c, 0xb4, 0xdd, 0x74, 0x45, 0x24, 0xf7, 0x84, 0x2b, 0x94, 0x2d, 0x08,
        0x77, 0x0d,
    ],
    [
        0xb0, 0x4e, 0x5e, 0xe3, 0x49, 0x08, 0x69, 0x85, 0xf7, 0x4b, 0x73, 0x97, 0x1c, 0xe9, 0xdf,
        0xe7, 0x6b, 0xbe, 0xd9, 0x5c, 0x84, 0x90, 0x6c, 0x5d, 0xff, 0xd9, 0x65, 0x04, 0xe1, 0xe5,
        0x39, 0x6c,
    ],
    [
        0xac, 0x50, 0x6e, 0xcb, 0x54, 0x65, 0x65, 0x9b, 0x3a, 0x92, 0x71, 0x43, 0xf6, 0xd7, 0x24,
        0xf9, 0x1d, 0x8d, 0x9c, 0x4b, 0xdb, 0x24, 0x63, 0xae, 0xe1, 0x11, 0xd9, 0xaa, 0x86, 0x98,
        0x74, 0xdb,
    ],
    [
        0x12, 0x4b, 0x05, 0xec, 0x27, 0x2c, 0xec, 0xd7, 0x53, 0x8f, 0xda, 0xfe, 0x53, 0xb6, 0x62,
        0x8d, 0x31, 0x18, 0x8f, 0xfb, 0x6f, 0x34, 0x51, 0x39, 0xaa, 0xc3, 0xc3, 0xc1, 0xfd, 0x2e,
        0x47, 0x0f,
    ],
    [
        0xc3, 0xbe, 0x9c, 0xbd, 0x19, 0x30, 0x4d, 0x84, 0xcc, 0xa3, 0xd0, 0x45, 0xe0, 0x6b, 0x8d,
        0xb3, 0xac, 0xd6, 0x8c, 0x30, 0x4f, 0xc9, 0xcd, 0x4c, 0xbf, 0xfe, 0x6d, 0x18, 0x03, 0x6c,
        0xb1, 0x3f,
    ],
    [
        0xfe, 0xf7, 0xbd, 0x9f, 0x88, 0x98, 0x11, 0xe5, 0x9e, 0x40, 0x76, 0xa0, 0x17, 0x40, 0x87,
        0x13, 0x5f, 0x08, 0x01, 0x77, 0x30, 0x27, 0x63, 0x01, 0x9a, 0xda, 0xf5, 0x31, 0x25, 0x7e,
        0x3a, 0x87,
    ],
    [
        0xa7, 0x07, 0xd1, 0xc6, 0x2d, 0x8b, 0xe6, 0x99, 0xd3, 0x4c, 0xb7, 0x48, 0x04, 0xfd, 0xd7,
        0xb4, 0xc5, 0x68, 0xb6, 0xc1, 0xa8, 0x21, 0x06, 0x6f, 0x12, 0x6c, 0x68, 0x0d, 0x4b, 0x83,
        0xe0, 0x0b,
    ],
    [
        0xf6, 0xe0, 0x93, 0x07, 0x0e, 0x03, 0x89, 0xd2, 0xe5, 0x29, 0xd6, 0x0f, 0xad, 0xb8, 0x55,
        0xfd, 0xde, 0xd5, 0x49, 0x76, 0xec, 0x50, 0xac, 0x70, 0x9e, 0x3a, 0x36, 0xce, 0xaa, 0x64,
        0xc2, 0x91,
    ],
    [
        0x37, 0x5a, 0x5b, 0xf9, 0x09, 0xcb, 0x02, 0x14, 0x3e, 0x36, 0x95, 0xca, 0x65, 0x8e, 0x06,
        0x41, 0xe7, 0x39, 0xaa, 0x59, 0x0f, 0x00, 0x04, 0xdb, 0xa9, 0x35, 0x72, 0xc4, 0x4c, 0xdb,
        0x9d, 0x2d,
    ],
];

///
/// L2 to l1 log structure, used for merkle tree leaves.
/// This structure holds both kinds of logs (user messages
/// and l1 -> l2 tx logs).
///
#[derive(Default, Debug, Clone)]
pub struct L2ToL1Log {
    ///
    /// Shard id.
    /// Deprecated, kept for compatibility, always set to 0.
    ///
    pub l2_shard_id: u8,
    ///
    /// Boolean flag.
    /// Deprecated, kept for compatibility, always set to `true`.
    ///
    pub is_service: bool,
    ///
    /// The L2 transaction number in a block, in which the log was sent
    ///
    pub tx_number_in_block: u16,
    ///
    /// The L2 address which sent the log.
    /// For user messages set to `L1Messenger` system hook address,
    /// for l1 -> l2 txs logs - `BootloaderFormalAddress`.
    ///
    pub sender: B160,
    ///
    /// The 32 bytes of information that was sent in the log.
    /// For user messages used to save message sender address(padded),
    /// for l1 -> l2 txs logs - transaction hash.
    ///
    pub key: Bytes32,
    ///
    /// The 32 bytes of information that was sent in the log.
    /// For user messages used to save message hash.
    /// for l1 -> l2 txs logs - success flag(padded).
    ///
    pub value: Bytes32,
}

///
/// Message/log content to be saved in the storage.
///
#[derive(Clone, Debug)]
pub struct GenericLogContent<IOTypes: SystemIOTypesConfig, A: Allocator = Global> {
    pub tx_number: u32,
    pub data: GenericLogContentData<UsizeAlignedByteBox<A>, Bytes32, IOTypes::Address>,
}

///
/// Data stored for a message/log.
/// Generic over data, hash and address type to represent both
/// the data and references to it.
///
#[derive(Clone, Debug)]
pub enum GenericLogContentData<DATA, HASH, ADDRESS> {
    UserMsg(UserMsgData<DATA, HASH, ADDRESS>),
    L1TxLog(L1TxLog<HASH>),
}
///
/// Data stored for a user message.
/// Generic over data, hash and address type to represent both
/// the data and references to it.
///
#[derive(Clone, Debug)]
pub struct UserMsgData<DATA, HASH, ADDRESS> {
    pub address: ADDRESS,
    pub data: DATA,
    pub data_hash: HASH,
}

///
/// Data stored for an l1->l2 tx log.
///
#[derive(Clone, Debug)]
pub struct L1TxLog<HASH> {
    pub tx_hash: HASH,
    pub success: bool,
}

/// Log content reference to be returned from the storage
///
#[derive(Clone, Debug)]
pub struct GenericLogContentWithTxRef<'a, IOTypes: SystemIOTypesConfig> {
    pub tx_number: u32,
    pub data: GenericLogContentData<&'a [u8], &'a Bytes32, &'a IOTypes::Address>,
}

impl<IOTypes: SystemIOTypesConfig, A: Allocator> GenericLogContent<IOTypes, A> {
    fn to_ref<'a>(&'a self) -> GenericLogContentWithTxRef<'a, IOTypes> {
        let data = match &self.data {
            GenericLogContentData::L1TxLog(l) => GenericLogContentData::L1TxLog(L1TxLog {
                tx_hash: &l.tx_hash,
                success: l.success,
            }),
            GenericLogContentData::UserMsg(m) => GenericLogContentData::UserMsg(UserMsgData {
                address: &m.address,
                data: m.data.as_slice(),
                data_hash: &m.data_hash,
            }),
        };
        GenericLogContentWithTxRef {
            tx_number: self.tx_number,
            data,
        }
    }

    pub fn from_ref<'a>(r: GenericLogContentWithTxRef<'a, IOTypes>, allocator: A) -> Self {
        let data = match r.data {
            GenericLogContentData::L1TxLog(l) => GenericLogContentData::L1TxLog(L1TxLog {
                tx_hash: *l.tx_hash,
                success: l.success,
            }),
            GenericLogContentData::UserMsg(m) => GenericLogContentData::UserMsg(UserMsgData {
                address: *m.address,
                data: UsizeAlignedByteBox::from_slice_in(m.data, allocator),
                data_hash: *m.data_hash,
            }),
        };
        GenericLogContent {
            tx_number: r.tx_number,
            data,
        }
    }
}

#[allow(type_alias_bounds)]
pub type LogContent<A: Allocator = Global> = GenericLogContent<EthereumIOTypesConfig, A>;

pub struct LogsStorage<SF: StackFactory<M>, const M: usize, A: Allocator + Clone = Global> {
    list: HistoryList<LogContent<A>, u32, SF, M, A>,
    pubdata_used_by_committed_logs: u32,
    _marker: core::marker::PhantomData<A>,
}

impl<SF: StackFactory<M>, const M: usize, A: Allocator + Clone + Default> LogsStorage<SF, M, A> {
    pub fn new_from_parts(allocator: A) -> Self {
        Self {
            list: HistoryList::new(allocator),
            pubdata_used_by_committed_logs: 0,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn begin_new_tx(&mut self) {
        self.pubdata_used_by_committed_logs = self.list.top().map_or(0, |(_, m)| *m);
    }

    #[track_caller]
    pub fn start_frame(&mut self) -> usize {
        self.list.snapshot()
    }

    pub fn push_message(
        &mut self,
        tx_number: u32,
        address: &B160,
        data: UsizeAlignedByteBox<A>,
        data_hash: Bytes32,
    ) -> Result<(), SystemError> {
        // We are publishing message data(4 bytes to encode length) and underlying log
        // TODO: double check that we should have 4 here
        let total_pubdata = 4 + data.len() + L2_TO_L1_LOG_SERIALIZE_SIZE;
        let total_pubdata = total_pubdata as u32;

        let total_pubdata = self
            .list
            .top()
            .map_or(total_pubdata, |(_, m)| *m + total_pubdata);

        self.list.push(
            LogContent {
                tx_number,
                data: GenericLogContentData::UserMsg(UserMsgData {
                    address: *address,
                    data,
                    data_hash,
                }),
            },
            total_pubdata,
        );

        Ok(())
    }

    pub fn push_l1_l2_tx_log(
        &mut self,
        tx_number: u32,
        tx_hash: Bytes32,
        success: bool,
    ) -> Result<(), SystemError> {
        let total_pubdata = L2_TO_L1_LOG_SERIALIZE_SIZE;
        let total_pubdata = total_pubdata as u32;

        let total_pubdata = self
            .list
            .top()
            .map_or(total_pubdata, |(_, m)| *m + total_pubdata);

        self.list.push(
            LogContent {
                tx_number,
                data: GenericLogContentData::L1TxLog(L1TxLog { tx_hash, success }),
            },
            total_pubdata,
        );

        Ok(())
    }

    pub fn len(&self) -> u64 {
        self.list.len() as u64
    }

    #[track_caller]
    pub fn finish_frame(&mut self, rollback_handle: Option<usize>) {
        if let Some(x) = rollback_handle {
            self.list.rollback(x);
        }
    }

    pub fn iter_net_diff(&self) -> impl Iterator<Item = &LogContent<A>> {
        self.list.iter()
    }

    pub fn messages_ref_iter(
        &'_ self,
    ) -> impl ExactSizeIterator<Item = GenericLogContentWithTxRef<'_, EthereumIOTypesConfig>> + Clone
    {
        self.list.iter().map(|message| message.to_ref())
    }

    pub fn apply_l2_to_l1_logs_hashes_to_hasher(&self, hasher: &mut impl MiniDigest) {
        for message in self.list.iter() {
            hasher.update(L2ToL1Log::from(message).hash().as_u8_ref());
        }
    }

    pub fn syscoin_edge_da_relay_message_for_tx_number(
        &self,
        authorized_tx_number: u32,
        canonical_relay_emitter: &B160,
    ) -> SyscoinEdgeDaRelayMessage {
        // SYSCOIN: Bind admission to exactly one *raw* message from the baked relay while the
        // transaction frame can still be rolled back. Canonical-looking messages from any other
        // emitter are deliberately ignored; malformed relay messages are never silently skipped.
        let mut canonical_message = None;
        // SYSCOIN: Retained logs are ordered by transaction number. Start at the current tail
        // so checking every Gateway transaction cannot repeatedly scan earlier transactions.
        for message in self.list.iter_rev() {
            if message.tx_number > authorized_tx_number {
                continue;
            }
            if message.tx_number < authorized_tx_number {
                break;
            }
            let GenericLogContentData::UserMsg(UserMsgData { address, data, .. }) = &message.data
            else {
                continue;
            };
            if address != canonical_relay_emitter {
                continue;
            }
            if canonical_message.is_some() {
                return SyscoinEdgeDaRelayMessage::Duplicate;
            }
            canonical_message = Some(data.as_slice());
        }

        let Some(message) = canonical_message else {
            return SyscoinEdgeDaRelayMessage::Missing;
        };
        let Some(ref_count) = syscoin_edge_da_ref_count(message) else {
            return SyscoinEdgeDaRelayMessage::Malformed;
        };
        // SYSCOIN: A single relay message may never exceed the same opening cap enforced for the
        // whole Gateway batch. Keeping the parser result out of the root on failure is fail-closed.
        if ref_count > SYSCOIN_DA_MAX_REFS_PER_BATCH {
            return SyscoinEdgeDaRelayMessage::Malformed;
        }
        let Some(ref_hash) = syscoin_edge_da_ref_hash(message) else {
            return SyscoinEdgeDaRelayMessage::Malformed;
        };

        SyscoinEdgeDaRelayMessage::Valid {
            ref_count,
            ref_hash,
        }
    }

    pub fn calculate_pubdata_used_by_tx(&self) -> Result<u32, InternalError> {
        let total_pubdata_used = self.list.top().map_or(0, |(_, m)| *m);

        if total_pubdata_used < self.pubdata_used_by_committed_logs {
            Err(internal_error!(
                "Pubdata used by logs unexpectedly decreased"
            ))
        } else {
            Ok(total_pubdata_used - self.pubdata_used_by_committed_logs)
        }
    }

    pub fn apply_pubdata<T: WriteBytes + ?Sized>(
        &self,
        dst: &mut T,
        results_keeper: &mut impl IOResultKeeper<EthereumIOTypesConfig>,
    ) {
        let logs_count = (self.list.len() as u32).to_be_bytes();
        dst.write(&logs_count);
        results_keeper.pubdata(&logs_count);
        let mut messages_count: u32 = 0;
        // First we encode all the L2L1 log information.
        self.list.iter().for_each(|el| {
            if let GenericLogContentData::UserMsg(_) = el.data {
                messages_count += 1;
            }
            let log: L2ToL1Log = el.into();
            log.write_encoding(dst);
            log.pubdata(results_keeper);
        });
        // Then, we do a second pass to publish messages
        let messages_count = messages_count.to_be_bytes();
        dst.write(&messages_count);
        results_keeper.pubdata(&messages_count);
        self.list.iter().for_each(|el| {
            if let GenericLogContentData::UserMsg(UserMsgData { data, .. }) = &el.data {
                let len = (data.as_slice().len() as u32).to_be_bytes();
                dst.write(&len);
                results_keeper.pubdata(&len);
                dst.write(data.as_slice());
                results_keeper.pubdata(data.as_slice());
            }
        })
    }

    pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
        self.list.iter().for_each(|el| {
            let log: L2ToL1Log = el.into();
            array_vec.push(log.hash())
        });
    }

    // we use it for tests to generate single block batches
    ///
    /// Calculate l2 logs merkle tree root.
    ///
    pub fn tree_root(&self) -> Bytes32 {
        let mut elements = alloc::vec::Vec::with_capacity_in(self.list.len(), A::default());
        self.list.iter().for_each(|el| {
            let log: L2ToL1Log = el.into();
            elements.push(log.hash())
        });
        let empty_hashes = L2_TO_L1_LOG_EMPTY_SUBTREE_HASHES.map(Bytes32::from_array);
        merkle_root_in_place::<crypto::sha3::Keccak256>(&mut elements, &empty_hashes)
    }
}

impl L2ToL1Log {
    ///
    /// Encode L2 to l1 log using solidity abi packed encoding.
    ///
    pub fn encode(&self) -> [u8; L2_TO_L1_LOG_SERIALIZE_SIZE] {
        let mut buffer = [0u8; L2_TO_L1_LOG_SERIALIZE_SIZE];
        buffer[0..1].copy_from_slice(&[self.l2_shard_id]);
        buffer[1..2].copy_from_slice(&[if self.is_service { 1 } else { 0 }]);
        buffer[2..4].copy_from_slice(&self.tx_number_in_block.to_be_bytes());
        buffer[4..24].copy_from_slice(&self.sender.to_be_bytes::<20>());
        buffer[24..56].copy_from_slice(self.key.as_u8_ref());
        buffer[56..88].copy_from_slice(self.value.as_u8_ref());
        buffer
    }

    ///
    /// Returns keccak hash of the l2 to l1 log solidity abi packed encoding.
    /// In fact, packed abi encoding in this case just equals to concatenation of all the fields big-endian representations.
    ///
    fn hash(&self) -> Bytes32 {
        let mut hasher = crypto::sha3::Keccak256::new();
        self.write_encoding(&mut hasher);
        hasher.finalize().into()
    }

    ///
    /// Adds the packed abi encoding of the log to the hasher.
    ///
    fn write_encoding<T: WriteBytes + ?Sized>(&self, dst: &mut T) {
        dst.write(&[self.l2_shard_id]);
        dst.write(&[if self.is_service { 1 } else { 0 }]);
        dst.write(&self.tx_number_in_block.to_be_bytes());
        dst.write(&self.sender.to_be_bytes::<20>());
        dst.write(self.key.as_u8_ref());
        dst.write(self.value.as_u8_ref());
    }

    ///
    /// Adds the packed abi encoding of the log to the pubdata.
    ///
    fn pubdata(&self, result_keeper: &mut impl IOResultKeeper<EthereumIOTypesConfig>) {
        result_keeper.pubdata(&[self.l2_shard_id]);
        result_keeper.pubdata(&[if self.is_service { 1 } else { 0 }]);
        result_keeper.pubdata(&self.tx_number_in_block.to_be_bytes());
        result_keeper.pubdata(&self.sender.to_be_bytes::<20>());
        result_keeper.pubdata(self.key.as_u8_ref());
        result_keeper.pubdata(self.value.as_u8_ref());
    }
}

impl<A: Allocator> From<&LogContent<A>> for L2ToL1Log {
    fn from(m: &LogContent<A>) -> Self {
        let (sender, key, value) = match m.data {
            GenericLogContentData::UserMsg(UserMsgData {
                address, data_hash, ..
            }) => (
                // TODO: move into const
                B160::from_limbs([0x8008, 0, 0]),
                address.into(),
                data_hash,
            ),
            GenericLogContentData::L1TxLog(L1TxLog { tx_hash, success }) => {
                let data = if success { U256::from(1) } else { U256::ZERO };
                (
                    // TODO: move into const
                    B160::from_limbs([0x8001, 0, 0]),
                    tx_hash,
                    Bytes32::from_u256_be(&data),
                )
            }
        };
        Self {
            l2_shard_id: 0,
            is_service: true,
            tx_number_in_block: m.tx_number as u16,
            sender,
            key,
            value,
        }
    }
}

// SYSCOIN: authenticate the canonical shape and commitment relation of
// abi.encode(uint8 version, uint256 chainId, uint256 batchNumber,
// bytes32 daCommitment, bytes blobHashes) emitted by the compact Gateway DA validator.
fn syscoin_edge_da_ref_count(message: &[u8]) -> Option<u32> {
    if message.len() < SYSCOIN_EDGE_DA_REF_HEAD_BYTES + ABI_WORD {
        return None;
    }
    if message[..31] != [0u8; 31] || message[31] != SYSCOIN_RELAYED_EDGE_DA_VALIDATOR_VERSION {
        return None;
    }
    // SYSCOIN: server and settlement contracts represent chain/batch identifiers as u64;
    // reject a wider ABI word in-guest so no proven message becomes host-unparseable later.
    if message[ABI_WORD..ABI_WORD + 24] != [0u8; 24]
        || message[ABI_WORD * 2..ABI_WORD * 2 + 24] != [0u8; 24]
    {
        return None;
    }
    let blob_hashes_offset = u256_word_to_usize(&message[ABI_WORD * 4..ABI_WORD * 5])?;
    if blob_hashes_offset != SYSCOIN_EDGE_DA_REF_HEAD_BYTES {
        return None;
    }
    let blob_hashes_len_offset = blob_hashes_offset;
    let blob_hashes_start = blob_hashes_len_offset + ABI_WORD;
    if message.len() < blob_hashes_start {
        return None;
    }
    let blob_hashes_len = u256_word_to_usize(&message[blob_hashes_len_offset..blob_hashes_start])?;
    if blob_hashes_len == 0 || blob_hashes_len % ABI_WORD != 0 {
        return None;
    }
    let blob_hashes_end = blob_hashes_start.checked_add(blob_hashes_len)?;
    if message.len() != blob_hashes_end {
        return None;
    }

    let mut commitment_hasher = crypto::sha3::Keccak256::new();
    commitment_hasher.update(&message[blob_hashes_start..blob_hashes_end]);
    let actual_commitment: Bytes32 = commitment_hasher.finalize().into();
    if message[ABI_WORD * 3..ABI_WORD * 4] != *actual_commitment.as_u8_array_ref() {
        return None;
    }

    u32::try_from(blob_hashes_len / ABI_WORD).ok()
}

fn syscoin_edge_da_ref_hash(message: &[u8]) -> Option<Bytes32> {
    let blob_count = syscoin_edge_da_ref_count(message)?;
    if blob_count > SYSCOIN_DA_MAX_REFS_PER_BATCH {
        return None;
    }
    let blob_hashes_len = usize::try_from(blob_count).ok()?.checked_mul(ABI_WORD)?;
    let blob_hashes_start = SYSCOIN_EDGE_DA_REF_HEAD_BYTES + ABI_WORD;
    let blob_hashes_end = blob_hashes_start.checked_add(blob_hashes_len)?;

    let mut hasher = crypto::sha3::Keccak256::new();
    hasher.update(SYSCOIN_EDGE_DA_REFS_DOMAIN);
    hasher.update(&message[ABI_WORD..ABI_WORD * 4]);
    hasher.update(U256::from(blob_count).to_be_bytes::<32>());
    hasher.update(&message[blob_hashes_start..blob_hashes_end]);
    Some(hasher.finalize().into())
}

fn u256_word_to_usize(word: &[u8]) -> Option<usize> {
    if word.len() != ABI_WORD || word[..24] != [0u8; 24] {
        return None;
    }
    usize::try_from(u64::from_be_bytes(word[24..].try_into().ok()?)).ok()
}

#[cfg(test)]
// SYSCOIN: Canonical Edge-DA envelope parsing, bounds, ordering, and authorization coverage.
mod tests {
    use super::*;
    use crate::common_structs::skip_list_quasi_vec::ListVec;
    use crate::memory::stack_implementations::vec_stack::VecStackFactory;

    struct ListVecStackFactory;

    impl StackFactory<2> for ListVecStackFactory {
        type Stack<T: Sized, const N: usize, A: Allocator + Clone> = ListVec<T, N, A>;

        fn new_in<T, A: Allocator + Clone>(allocator: A) -> Self::Stack<T, 2, A> {
            ListVec::new_in(allocator)
        }
    }

    fn edge_da_message(
        chain_id: U256,
        batch_number: U256,
        da_commitment: [u8; 32],
        blob_hashes: &[[u8; 32]],
    ) -> alloc::vec::Vec<u8> {
        let mut message = alloc::vec::Vec::with_capacity(
            SYSCOIN_EDGE_DA_REF_HEAD_BYTES + ABI_WORD + blob_hashes.len() * ABI_WORD,
        );
        let mut version = [0u8; ABI_WORD];
        version[ABI_WORD - 1] = SYSCOIN_RELAYED_EDGE_DA_VALIDATOR_VERSION;
        message.extend_from_slice(&version);
        message.extend_from_slice(&chain_id.to_be_bytes::<32>());
        message.extend_from_slice(&batch_number.to_be_bytes::<32>());
        message.extend_from_slice(&da_commitment);
        message.extend_from_slice(&U256::from(SYSCOIN_EDGE_DA_REF_HEAD_BYTES).to_be_bytes::<32>());
        message.extend_from_slice(&U256::from(blob_hashes.len() * ABI_WORD).to_be_bytes::<32>());
        for blob_hash in blob_hashes {
            message.extend_from_slice(blob_hash);
        }
        message
    }

    fn edge_da_commitment(blob_hashes: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher = crypto::sha3::Keccak256::new();
        for blob_hash in blob_hashes {
            hasher.update(blob_hash);
        }
        hasher.finalize()
    }

    fn expected_edge_da_ref_hash(
        chain_id: U256,
        batch_number: U256,
        da_commitment: [u8; 32],
        blob_hashes: &[[u8; 32]],
    ) -> Bytes32 {
        let mut hasher = crypto::sha3::Keccak256::new();
        hasher.update(SYSCOIN_EDGE_DA_REFS_DOMAIN);
        hasher.update(chain_id.to_be_bytes::<32>());
        hasher.update(batch_number.to_be_bytes::<32>());
        hasher.update(da_commitment);
        hasher.update(U256::from(blob_hashes.len()).to_be_bytes::<32>());
        for blob_hash in blob_hashes {
            hasher.update(blob_hash);
        }
        hasher.finalize().into()
    }

    fn extend_root(root: Bytes32, edge_ref_hash: Bytes32) -> Bytes32 {
        let mut hasher = crypto::sha3::Keccak256::new();
        hasher.update(root.as_u8_ref());
        hasher.update(edge_ref_hash.as_u8_ref());
        hasher.finalize().into()
    }

    #[test]
    fn syscoin_edge_da_ref_parser_authenticates_canonical_encoding() {
        let chain_id = U256::from(57u64);
        let batch_number = U256::from(91u64);
        let blob_hashes = [[0x22; 32], [0x33; 32]];
        let commitment = edge_da_commitment(&blob_hashes);
        let message = edge_da_message(chain_id, batch_number, commitment, &blob_hashes);

        assert_eq!(
            syscoin_edge_da_ref_hash(&message),
            Some(expected_edge_da_ref_hash(
                chain_id,
                batch_number,
                commitment,
                &blob_hashes,
            ))
        );

        let mut wrong_version = message.clone();
        wrong_version[ABI_WORD - 1] += 1;
        assert_eq!(syscoin_edge_da_ref_hash(&wrong_version), None);

        let mut wrong_offset = message.clone();
        wrong_offset[ABI_WORD * 5 - 1] -= ABI_WORD as u8;
        assert_eq!(syscoin_edge_da_ref_hash(&wrong_offset), None);

        let oversized_chain = edge_da_message(
            U256::from(u64::MAX) + U256::ONE,
            batch_number,
            commitment,
            &blob_hashes,
        );
        assert_eq!(syscoin_edge_da_ref_count(&oversized_chain), None);

        let oversized_batch = edge_da_message(
            chain_id,
            U256::from(u64::MAX) + U256::ONE,
            commitment,
            &blob_hashes,
        );
        assert_eq!(syscoin_edge_da_ref_count(&oversized_batch), None);

        let mut unaligned_length = message.clone();
        unaligned_length[ABI_WORD * 6 - 1] += 1;
        unaligned_length.push(0);
        assert_eq!(syscoin_edge_da_ref_hash(&unaligned_length), None);

        let mut trailing_byte = message;
        trailing_byte.push(0);
        assert_eq!(syscoin_edge_da_ref_hash(&trailing_byte), None);

        let commitment_mismatch = edge_da_message(chain_id, batch_number, [0x11; 32], &blob_hashes);
        assert_eq!(syscoin_edge_da_ref_count(&commitment_mismatch), None);
        assert_eq!(syscoin_edge_da_ref_hash(&commitment_mismatch), None);

        let exact_limit_hashes = [[0x44; 32]; SYSCOIN_DA_MAX_REFS_PER_BATCH as usize];
        let exact_limit = edge_da_message(
            chain_id,
            batch_number,
            edge_da_commitment(&exact_limit_hashes),
            &exact_limit_hashes,
        );
        assert_eq!(
            syscoin_edge_da_ref_count(&exact_limit),
            Some(SYSCOIN_DA_MAX_REFS_PER_BATCH)
        );
        assert!(syscoin_edge_da_ref_hash(&exact_limit).is_some());

        let over_limit_hashes = [[0x55; 32]; SYSCOIN_DA_MAX_REFS_PER_BATCH as usize + 1];
        let over_limit = edge_da_message(
            chain_id,
            batch_number,
            edge_da_commitment(&over_limit_hashes),
            &over_limit_hashes,
        );
        // SYSCOIN: The count remains observable to the tx loop so it can classify and roll back
        // the overflowing transaction, while the root builder refuses to prove it.
        assert_eq!(
            syscoin_edge_da_ref_count(&over_limit),
            Some(SYSCOIN_DA_MAX_REFS_PER_BATCH + 1)
        );
        assert_eq!(syscoin_edge_da_ref_hash(&over_limit), None);
    }

    #[test]
    fn syscoin_edge_da_relay_analyzer_binds_exact_emitter_and_message_count() {
        let relay = B160::from_be_bytes([0x11; 20]);
        let spoof = B160::from_be_bytes([0x22; 20]);
        let first_hashes = [[0x51; 32]];
        let first = edge_da_message(
            U256::from(57u64),
            U256::from(1u64),
            edge_da_commitment(&first_hashes),
            &first_hashes,
        );
        let second_hashes = [[0x52; 32]];
        let second = edge_da_message(
            U256::from(57u64),
            U256::from(2u64),
            edge_da_commitment(&second_hashes),
            &second_hashes,
        );
        let first_hash = syscoin_edge_da_ref_hash(&first).unwrap();

        let mut logs = LogsStorage::<VecStackFactory, 8>::new_from_parts(Global);
        // SYSCOIN: a canonical-looking message from a different emitter is not authority.
        logs.push_message(
            2,
            &spoof,
            UsizeAlignedByteBox::from_slice_in(&first, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(2, &relay),
            SyscoinEdgeDaRelayMessage::Missing
        );

        // SYSCOIN: unrelated messages remain ignored once the one canonical relay message exists.
        logs.push_message(
            2,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&first, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(2, &relay),
            SyscoinEdgeDaRelayMessage::Valid {
                ref_count: 1,
                ref_hash: first_hash,
            }
        );

        // SYSCOIN: a second raw message from the relay is a duplicate even if both parse.
        logs.push_message(
            2,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&second, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(2, &relay),
            SyscoinEdgeDaRelayMessage::Duplicate
        );

        // SYSCOIN: malformed data cannot be hidden behind one otherwise valid relay message.
        logs.push_message(
            3,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&first, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        logs.push_message(
            3,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&[0xff; 32], Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(3, &relay),
            SyscoinEdgeDaRelayMessage::Duplicate
        );
    }

    #[test]
    fn syscoin_edge_da_relay_analyzer_rejects_malformed_and_oversized_messages() {
        let relay = B160::from_be_bytes([0x33; 20]);
        let mut logs = LogsStorage::<VecStackFactory, 8>::new_from_parts(Global);

        logs.push_message(
            4,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&[0xff; 32], Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(4, &relay),
            SyscoinEdgeDaRelayMessage::Malformed
        );

        // SYSCOIN: a structurally canonical envelope carrying zero openings is still invalid.
        let empty_hashes: [[u8; 32]; 0] = [];
        let empty = edge_da_message(
            U256::from(57u64),
            U256::from(7u64),
            edge_da_commitment(&empty_hashes),
            &empty_hashes,
        );
        logs.push_message(
            7,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&empty, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(7, &relay),
            SyscoinEdgeDaRelayMessage::Malformed
        );

        let oversized_hashes = [[0x44; 32]; SYSCOIN_DA_MAX_REFS_PER_BATCH as usize + 1];
        let oversized = edge_da_message(
            U256::from(57u64),
            U256::from(5u64),
            edge_da_commitment(&oversized_hashes),
            &oversized_hashes,
        );
        logs.push_message(
            5,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&oversized, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(5, &relay),
            SyscoinEdgeDaRelayMessage::Malformed
        );

        let exact_limit_hashes = [[0x45; 32]; SYSCOIN_DA_MAX_REFS_PER_BATCH as usize];
        let exact_limit = edge_da_message(
            U256::from(57u64),
            U256::from(6u64),
            edge_da_commitment(&exact_limit_hashes),
            &exact_limit_hashes,
        );
        let exact_limit_hash = syscoin_edge_da_ref_hash(&exact_limit).unwrap();
        logs.push_message(
            6,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&exact_limit, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(6, &relay),
            SyscoinEdgeDaRelayMessage::Valid {
                ref_count: SYSCOIN_DA_MAX_REFS_PER_BATCH,
                ref_hash: exact_limit_hash,
            }
        );
    }

    #[test]
    fn syscoin_edge_da_relay_analysis_observes_log_rollback() {
        let relay = B160::from_be_bytes([0x55; 20]);
        let blob_hashes = [[0x66; 32]];
        let message = edge_da_message(
            U256::from(57u64),
            U256::from(6u64),
            edge_da_commitment(&blob_hashes),
            &blob_hashes,
        );
        let mut logs = LogsStorage::<VecStackFactory, 8>::new_from_parts(Global);
        let rollback_handle = logs.start_frame();
        logs.push_message(
            6,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&message, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert!(matches!(
            logs.syscoin_edge_da_relay_message_for_tx_number(6, &relay),
            SyscoinEdgeDaRelayMessage::Valid { .. }
        ));
        logs.finish_frame(Some(rollback_handle));
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(6, &relay),
            SyscoinEdgeDaRelayMessage::Missing
        );
    }

    fn check_syscoin_edge_da_reverse_analysis<SF: StackFactory<2>>() {
        let relay = B160::from_be_bytes([0x55; 20]);
        let unrelated = B160::from_be_bytes([0x77; 20]);
        let blob_hashes = [[0x66; 32]];
        let message = edge_da_message(
            U256::from(57u64),
            U256::from(1u64),
            edge_da_commitment(&blob_hashes),
            &blob_hashes,
        );
        let mut logs = LogsStorage::<SF, 2>::new_from_parts(Global);
        assert!(logs.list.iter_rev().next().is_none());
        for (tx_number, emitter) in [(1, relay), (2, unrelated), (2, unrelated), (3, relay)] {
            logs.push_message(
                tx_number,
                &emitter,
                UsizeAlignedByteBox::from_slice_in(&message, Global),
                Bytes32::ZERO,
            )
            .unwrap();
        }
        let mut reversed = logs.list.iter_rev().map(|log| log.tx_number);
        assert_eq!(reversed.next(), Some(3));
        let cloned = reversed.clone();
        assert_eq!(reversed.collect::<alloc::vec::Vec<_>>(), [2, 2, 1]);
        assert_eq!(cloned.collect::<alloc::vec::Vec<_>>(), [2, 2, 1]);

        for tx_number in [1, 3] {
            assert!(matches!(
                logs.syscoin_edge_da_relay_message_for_tx_number(tx_number, &relay),
                SyscoinEdgeDaRelayMessage::Valid { ref_count: 1, .. }
            ));
        }
        for tx_number in [0, 2, 4] {
            assert_eq!(
                logs.syscoin_edge_da_relay_message_for_tx_number(tx_number, &relay),
                SyscoinEdgeDaRelayMessage::Missing
            );
        }

        let rollback_handle = logs.start_frame();
        logs.push_message(
            3,
            &relay,
            UsizeAlignedByteBox::from_slice_in(&message, Global),
            Bytes32::ZERO,
        )
        .unwrap();
        assert_eq!(
            logs.syscoin_edge_da_relay_message_for_tx_number(3, &relay),
            SyscoinEdgeDaRelayMessage::Duplicate
        );
        logs.finish_frame(Some(rollback_handle));
        assert_eq!(
            logs.list
                .iter_rev()
                .map(|log| log.tx_number)
                .collect::<alloc::vec::Vec<_>>(),
            [3, 2, 2, 1]
        );
        assert!(matches!(
            logs.syscoin_edge_da_relay_message_for_tx_number(3, &relay),
            SyscoinEdgeDaRelayMessage::Valid { ref_count: 1, .. }
        ));
    }

    #[test]
    fn syscoin_edge_da_reverse_analysis_vec_observes_tx_boundaries_and_rollback() {
        check_syscoin_edge_da_reverse_analysis::<VecStackFactory>();
    }

    #[test]
    fn syscoin_edge_da_reverse_analysis_list_vec_observes_tx_boundaries_and_rollback() {
        check_syscoin_edge_da_reverse_analysis::<ListVecStackFactory>();
    }

    #[test]
    fn syscoin_edge_da_root_folds_prevalidated_hashes_in_order() {
        let first = Bytes32::from_array([0x71; 32]);
        let second = Bytes32::from_array([0x72; 32]);

        let expected = extend_root(extend_root(Bytes32::ZERO, first), second);
        assert_eq!(
            syscoin_edge_da_refs_root_from_hashes(&[first, second]),
            expected
        );
        assert_eq!(
            syscoin_edge_da_refs_root_from_hashes(&[second]),
            extend_root(Bytes32::ZERO, second)
        );

        let reversed_root = extend_root(extend_root(Bytes32::ZERO, second), first);
        assert_eq!(
            syscoin_edge_da_refs_root_from_hashes(&[second, first]),
            reversed_root
        );
        assert_ne!(reversed_root, expected);
    }
}
