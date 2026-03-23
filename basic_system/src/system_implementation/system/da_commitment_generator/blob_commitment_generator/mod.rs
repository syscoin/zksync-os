use crate::system_implementation::system::da_commitment_generator::DACommitmentGenerator;
use arrayvec::ArrayVec;
use crypto::sha3::Keccak256;
use crypto::MiniDigest;
use zk_ee::oracle::IOOracle;
use zk_ee::utils::write_bytes::WriteBytes;
use zk_ee::utils::Bytes32;

pub mod brp_roots_of_unity;
pub mod commitment_and_proof_advice;
pub mod polynomial_evaluation;

///
/// Number of bytes we encode in one blob element
///
pub const BLOB_CHUNK_SIZE: usize = 31;

///
/// Number of field elements per EIP-4844 blob
///
pub const ELEMENTS_PER_4844_BLOB: usize = 4096;

///
/// Number of bytes we can encode in one blob
///
pub const ENCODABLE_BYTES_PER_BLOB: usize = BLOB_CHUNK_SIZE * ELEMENTS_PER_4844_BLOB;

///
/// Maximal number of blobs that we support with blobs DA mode.
///
pub const MAX_NUMBER_OF_BLOBS: usize = 9;

pub const BUFFER_CAPACITY: usize = ENCODABLE_BYTES_PER_BLOB * MAX_NUMBER_OF_BLOBS;

///
/// Blobs DA commitment generator.
///
/// It encodes pubdata into the blobs using alloy default(`SimpleCoder`) encoding.
/// The first element in the first blob used to encode length as `[0, len BE, 23 zeroes] BE`.
/// Then blobs are filled with elements created from data chunked by 31 byte as `[0, chunk(31 byte)] BE`.
///
pub struct BlobCommitmentGenerator {
    buffer: ArrayVec<u8, BUFFER_CAPACITY>,
    versioned_hashes_hasher: Keccak256,
}

impl BlobCommitmentGenerator {
    pub fn new() -> Self {
        let mut buffer = ArrayVec::new();
        // we allocate 31 byte to encode length as a separate field element for convenience
        buffer.extend([0u8; 31]);
        Self {
            buffer,
            versioned_hashes_hasher: Keccak256::new(),
        }
    }
}

impl WriteBytes for BlobCommitmentGenerator {
    fn write(&mut self, buf: &[u8]) {
        // overflow shouldn't be reachable, operator validates pubdata limit during forward run
        self.buffer.try_extend_from_slice(buf).unwrap()
    }
}

impl<O: IOOracle> DACommitmentGenerator<O> for BlobCommitmentGenerator {
    fn finalize(&mut self, _oracle: &mut O) -> Bytes32 {
        // len should be [0, len be, 23 zeroes] BE
        let length = self.buffer.len() - 31;
        self.buffer[0..8].copy_from_slice(&(length as u64).to_be_bytes());
        for chunk in self.buffer.chunks(ENCODABLE_BYTES_PER_BLOB) {
            cycle_marker::wrap!("blob_data_id", {
                self.versioned_hashes_hasher
                    .update(&blob_data_id(chunk));
            });
        }
        self.versioned_hashes_hasher.finalize_reset().into()
    }
}

/// SYSCOIN Returns the Syscoin publication id for an encoded blob chunk.
pub fn blob_data_id(data: &[u8]) -> [u8; 32] {
    debug_assert!(data.len() <= ENCODABLE_BYTES_PER_BLOB);
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize()
}
