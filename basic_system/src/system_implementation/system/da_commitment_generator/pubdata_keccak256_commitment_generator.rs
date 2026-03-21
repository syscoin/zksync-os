use crate::system_implementation::system::da_commitment_generator::DACommitmentGenerator;
use crypto::blake2s::Blake2s256;
use crypto::sha3::Keccak256;
use crypto::MiniDigest;
use zk_ee::oracle::IOOracle;
use zk_ee::utils::write_bytes::WriteBytes;
use zk_ee::utils::Bytes32;

pub struct PubdataKeccak256CommitmentGenerator {
    pubdata_hasher: Keccak256,
    state_diffs_hash: Bytes32,
}

impl PubdataKeccak256CommitmentGenerator {
    pub fn new() -> Self {
        Self {
            pubdata_hasher: Keccak256::new(),
            state_diffs_hash: Blake2s256::new().finalize().into(),
        }
    }
}

impl WriteBytes for PubdataKeccak256CommitmentGenerator {
    fn write(&mut self, buf: &[u8]) {
        self.pubdata_hasher.update(buf);
    }
}

impl<O: IOOracle> DACommitmentGenerator<O> for PubdataKeccak256CommitmentGenerator {
    fn finalize(&mut self, _oracle: &mut O) -> Bytes32 {
        let mut da_commitment_hasher = Keccak256::new();
        da_commitment_hasher.update(self.state_diffs_hash.as_u8_ref());
        da_commitment_hasher.update(self.pubdata_hasher.finalize_reset());
        da_commitment_hasher.finalize().into()
    }

    fn set_state_diffs_hash(&mut self, state_diffs_hash: &Bytes32) {
        self.state_diffs_hash = *state_diffs_hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_ee::oracle::IOOracle;
    use zk_ee::system::errors::internal::InternalError;

    struct DummyOracle;

    impl IOOracle for DummyOracle {
        type RawIterator<'a> = core::iter::Empty<usize>;

        fn raw_query<'a, I: zk_ee::oracle::usize_serialization::UsizeSerializable + zk_ee::oracle::usize_serialization::UsizeDeserializable>(
            &'a mut self,
            _query_type: u32,
            _input: &I,
        ) -> Result<Self::RawIterator<'a>, InternalError> {
            Ok(core::iter::empty())
        }
    }

    #[test]
    fn finalizes_expected_short_commitment() {
        let mut generator = PubdataKeccak256CommitmentGenerator::new();
        generator.write(b"pubdata");

        let mut state_diffs_hasher = Blake2s256::new();
        state_diffs_hasher.update([0x11; 32]);
        state_diffs_hasher.update([0x22; 32]);
        state_diffs_hasher.update([0x33; 32]);
        state_diffs_hasher.update([0x44; 32]);
        generator.set_state_diffs_hash(&state_diffs_hasher.finalize().into());

        let mut pubdata_hasher = Keccak256::new();
        pubdata_hasher.update(b"pubdata");

        let mut expected_hasher = Keccak256::new();
        expected_hasher.update(generator.state_diffs_hash.as_u8_ref());
        expected_hasher.update(pubdata_hasher.finalize());

        let mut oracle = DummyOracle;
        assert_eq!(
            generator.finalize(&mut oracle),
            Bytes32::from_array(expected_hasher.finalize())
        );
    }
}
