use crate::utils::evaluate::read_memory_as_u8;
use crate::utils::usize_slice_iterator::UsizeSliceIteratorOwned;
use basic_bootloader::bootloader::block_flow::zk::da_commitment_generator::KZGCommitmentAndProof;
use basic_bootloader::bootloader::block_flow::zk::da_commitment_generator::BLOB_COMMITMENT_AND_PROOF_QUERY_ID;
use crypto::sha3::Keccak256;
use crypto::MiniDigest;
use oracle_provider::OracleQueryProcessor;
use risc_v_simulator::abstractions::memory::MemorySource;
use zk_ee::oracle::usize_serialization::UsizeSerializable;

///
/// Query processor, which returns blob kzg commitment and proof for a given data.
///
/// Proof is basically kzg proof in a point derived from data and kzg commitment,
/// so it allows to verify kzg commitment correctness by validating this proof and value of the polynomial in this point.
///
pub struct BlobCommitmentAndProofQuery<M: MemorySource> {
    _marker: std::marker::PhantomData<M>,
}

impl<M: MemorySource> Default for BlobCommitmentAndProofQuery<M> {
    fn default() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<M: MemorySource> OracleQueryProcessor<M> for BlobCommitmentAndProofQuery<M> {
    fn supported_query_ids(&self) -> Vec<u32> {
        vec![BLOB_COMMITMENT_AND_PROOF_QUERY_ID]
    }

    fn process_buffered_query(
        &mut self,
        query_id: u32,
        query: Vec<usize>,
        memory: &M,
    ) -> Box<dyn ExactSizeIterator<Item = usize> + 'static + Send + Sync> {
        debug_assert!(self.supports_query_id(query_id));

        // this query processor supposed to work only on "host" architecture, which is always 64 bit
        const { assert!(8 == core::mem::size_of::<usize>()) };
        let mut it = query.into_iter();

        // Even though on riscv32 pointer and length are 32 bits, they are encoded as u64 and take a whole 64-bit word here
        let data_ptr = it.next().unwrap() as u32;
        let data_len = it.next().unwrap() as u32;
        assert!(
            it.next().is_none(),
            "RISC-V ptr and len should've been passed."
        );

        assert!(data_ptr.is_multiple_of(4));

        let data = read_memory_as_u8(memory, data_ptr, data_len).unwrap();
        let result = blob_kzg_commitment_and_proof(&data);

        let r = result.iter().collect::<Vec<_>>();
        let r = Vec::into_boxed_slice(r);
        let n = UsizeSliceIteratorOwned::new(r);
        Box::new(n)
    }
}

/// SYSCOIN: Keep the legacy function name/interface, but return blob data id
/// packed into the legacy struct for compatibility.
pub fn blob_kzg_commitment_and_proof(data: &[u8]) -> KZGCommitmentAndProof {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let blob_data_id: [u8; 32] = hasher.finalize();

    let mut commitment = [0u8; 48];
    commitment[..32].copy_from_slice(&blob_data_id);
    let proof = [0u8; 48];

    KZGCommitmentAndProof { commitment, proof }
}
