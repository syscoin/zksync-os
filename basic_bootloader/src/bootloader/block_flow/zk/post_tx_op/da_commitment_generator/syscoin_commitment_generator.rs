use super::DACommitmentGenerator;
use alloc::alloc::Allocator;
use alloc::vec::Vec;
use crypto::sha3::Keccak256;
use crypto::MiniDigest;
use zk_ee::oracle::IOOracle;
use zk_ee::utils::write_bytes::WriteBytes;
use zk_ee::utils::Bytes32;

///
/// SYSCOIN: Number of bytes included in one compact DA data-ID chunk.
///
pub const COMPACT_DA_CHUNK_BYTES: usize = 2 * 1024 * 1024;

///
/// SYSCOIN: Maximum number of compact DA data-ID chunks in one batch.
///
pub const MAX_COMPACT_DA_CHUNKS: usize = 32;

pub const BUFFER_CAPACITY: usize = COMPACT_DA_CHUNK_BYTES * MAX_COMPACT_DA_CHUNKS;

///
/// SYSCOIN: Compact Bitcoin-DA commitment generator selected for Syscoin's
/// `BlobsZKsyncOS` protocol mode. The upstream KZG generator remains intact in
/// `blob_commitment_generator`; only the scheme-selection branch is downstream.
///
/// It prefixes the batch pubdata with its big-endian length, splits the resulting bytes into
/// bounded chunks, computes each Blake2s data ID in the guest, and hashes the ordered data IDs
/// into the batch DA commitment.
///
pub struct SyscoinDACommitmentGenerator<A: Allocator> {
    // SYSCOIN: Keep the 64 MiB protocol capacity in the guest allocator. An inline
    // ArrayVec makes this entire temporary part of every post-op stack frame, even
    // when another DA scheme is selected, and overflows proof-input execution.
    buffer: Vec<u8, A>,
    data_ids_hasher: Keccak256,
}

impl<A: Allocator> SyscoinDACommitmentGenerator<A> {
    pub fn new_in(allocator: A) -> Self {
        let mut buffer = Vec::with_capacity_in(BUFFER_CAPACITY, allocator);
        // we allocate 31 byte to encode length as a separate field element for convenience
        buffer.extend([0u8; 31]);
        Self {
            buffer,
            data_ids_hasher: Keccak256::new(),
        }
    }
}

impl<A: Allocator> WriteBytes for SyscoinDACommitmentGenerator<A> {
    fn write(&mut self, buf: &[u8]) {
        // SYSCOIN: Preserve ArrayVec's fail-closed protocol bound after moving the
        // storage off-stack; forward execution should already enforce this limit.
        let new_len = self
            .buffer
            .len()
            .checked_add(buf.len())
            .expect("compact Syscoin DA buffer length overflow");
        assert!(
            new_len <= BUFFER_CAPACITY,
            "compact Syscoin DA pubdata exceeds the guest buffer capacity"
        );
        self.buffer.extend_from_slice(buf);
    }
}

impl<A: Allocator, O: IOOracle> DACommitmentGenerator<O> for SyscoinDACommitmentGenerator<A> {
    fn finalize(&mut self, _oracle: &mut O) -> Bytes32 {
        // len should be [0, len be, 23 zeroes] BE
        let length = self.buffer.len() - 31;
        self.buffer[0..8].copy_from_slice(&(length as u64).to_be_bytes());
        for chunk in self.buffer.chunks(COMPACT_DA_CHUNK_BYTES) {
            cycle_marker::wrap!("blob_data_id", {
                // SYSCOIN: Bitcoin-DA IDs are consensus-derived in-guest; host advice is neither
                // needed nor trusted for this compact Blake2s computation.
                self.data_ids_hasher.update(&blob_data_id(chunk));
            });
        }
        self.data_ids_hasher.finalize_reset().into()
    }
}

fn blob_data_id(data: &[u8]) -> [u8; 32] {
    debug_assert!(data.len() <= COMPACT_DA_CHUNK_BYTES);
    crypto::blake2s::Blake2s256::digest(data)
}

#[cfg(test)]
// SYSCOIN: Compact Bitcoin-DA stack, hash-vector, and chunk-boundary regression coverage.
mod tests {
    use super::*;
    use alloc::alloc::Global;

    fn expected_compact_da_commitment(payload: &[u8]) -> Bytes32 {
        // Build the protocol preimage independently from the generator's streaming state: an
        // eight-byte big-endian payload length, 23 zero bytes, then the batch pubdata.
        let mut preimage = alloc::vec![0u8; 31];
        preimage[0..8].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        preimage.extend_from_slice(payload);

        let mut ordered_data_ids = Vec::new();
        for chunk in preimage.chunks(COMPACT_DA_CHUNK_BYTES) {
            ordered_data_ids.extend_from_slice(&crypto::blake2s::Blake2s256::digest(chunk));
        }
        Keccak256::digest(&ordered_data_ids).into()
    }

    fn assert_compact_da_commitment(payload: &[u8]) {
        let mut generator = SyscoinDACommitmentGenerator::new_in(Global);
        generator.write(payload);
        let mut oracle = DummyOracle;
        assert_eq!(
            generator.finalize(&mut oracle),
            expected_compact_da_commitment(payload)
        );
    }

    struct DummyOracle;

    impl IOOracle for DummyOracle {
        type RawIterator<'a> = core::iter::Empty<usize>;

        fn raw_query<
            'a,
            I: zk_ee::oracle::usize_serialization::UsizeSerializable
                + zk_ee::oracle::usize_serialization::UsizeDeserializable,
        >(
            &'a mut self,
            _query_type: u32,
            _input: &I,
        ) -> Result<Self::RawIterator<'a>, zk_ee::system::errors::internal::InternalError> {
            Ok(core::iter::empty())
        }
    }

    #[test]
    fn compact_da_buffer_is_not_inline_in_the_post_op_stack() {
        // SYSCOIN: Regression guard for the 64 MiB ArrayVec that overflowed even
        // Keccak proof-input runs because the runtime match reserved its stack slot.
        assert!(core::mem::size_of::<SyscoinDACommitmentGenerator<Global>>() < 1024);
    }

    #[test]
    fn computes_standard_blake2s_vector() {
        assert_eq!(
            blob_data_id(b"abc"),
            [
                0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb,
                0x45, 0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c,
                0x86, 0x67, 0x59, 0x82,
            ]
        );
    }

    #[test]
    fn compact_da_commitment_matches_one_chunk_boundary() {
        // SYSCOIN: The 31-byte length prefix must count toward the 2 MiB data-ID boundary.
        let payload = alloc::vec![0x5a; COMPACT_DA_CHUNK_BYTES - 31];
        assert_compact_da_commitment(&payload);
    }

    #[test]
    fn compact_da_commitment_matches_two_chunks_after_boundary() {
        let payload = alloc::vec![0xa5; COMPACT_DA_CHUNK_BYTES - 30];
        assert_compact_da_commitment(&payload);
    }
}
