use self::commitment_and_proof_advice::{
    BlobCommitmentAndProofAdvisor, OracleBasedBlobCommitmentAndProofAdvisor,
};
use super::DACommitmentGenerator;
use arrayvec::ArrayVec;
use crypto::ark_ff::{Field, One, PrimeField, Zero};
use crypto::sha3::Keccak256;
use crypto::{parse_u256_be, MiniDigest};
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
// SYSCOIN: Bitcoin DA accepts up to 2 MiB per blob; keep the legacy constant
// name because the rest of the DA commitment path is keyed off this value.
pub const ENCODABLE_BYTES_PER_BLOB: usize = 2 * 1024 * 1024;

///
/// Maximal number of blobs that we support with blobs DA mode.
///
// SYSCOIN: Allow a batch to commit up to 32 Bitcoin-DA payload chunks.
pub const MAX_NUMBER_OF_BLOBS: usize = 32;

pub const BUFFER_CAPACITY: usize = ENCODABLE_BYTES_PER_BLOB * MAX_NUMBER_OF_BLOBS;

///
/// Blobs DA commitment generator.
///
/// SYSCOIN: It retains the legacy 31-byte length prefix in the committed byte
/// stream, splits that stream into Bitcoin-DA payload chunks, and commits each
/// chunk by its Blake2s data id. No EIP-4844 field-element encoding is applied.
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
    fn finalize(&mut self, oracle: &mut O) -> Bytes32 {
        // len should be [0, len be, 23 zeroes] BE
        let length = self.buffer.len() - 31;
        self.buffer[0..8].copy_from_slice(&(length as u64).to_be_bytes());
        let mut advisor = OracleBasedBlobCommitmentAndProofAdvisor { oracle };
        for chunk in self.buffer.chunks(ENCODABLE_BYTES_PER_BLOB) {
            cycle_marker::wrap!("blob_versioned_hash", {
                self.versioned_hashes_hasher
                    .update(&blob_versioned_hash_with_advisor(chunk, &mut advisor));
            });
        }
        self.versioned_hashes_hasher.finalize_reset().into()
    }
}

///
/// Returns the Blake2s data id for one Bitcoin-DA payload chunk.
///
/// SYSCOIN: The advisor transports the data id in the first 32 bytes of the
/// legacy commitment field. This function recomputes the id locally and rejects
/// inconsistent advice; the legacy proof field is not a KZG proof in this mode.
///
pub fn blob_versioned_hash_with_advisor(
    data: &[u8],
    advisor: &mut impl BlobCommitmentAndProofAdvisor,
) -> [u8; 32] {
    debug_assert!(data.len() <= ENCODABLE_BYTES_PER_BLOB);

    // SYSCOIN: Retrieve the compatibility payload from the advisor and bind it
    // to the locally recomputed Bitcoin-DA data id.
    let commitment_and_proof = advisor.get_blob_commitment_and_proof_advice(data);
    let mut advised_blob_data_id = [0u8; 32];
    advised_blob_data_id.copy_from_slice(&commitment_and_proof.commitment[..32]);
    let local_blob_data_id = blob_data_id(data);

    assert_eq!(
        advised_blob_data_id, local_blob_data_id,
        "Blob data id advice mismatch"
    );

    local_blob_data_id
}

fn blob_data_id(data: &[u8]) -> [u8; 32] {
    crypto::blake2s::Blake2s256::digest(data)
}
