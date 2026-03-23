#![cfg(test)]

use crypto::sha3::Keccak256;
use crypto::MiniDigest;
use rig::{
    basic_system::system_implementation::system::da_commitment_generator::blob_commitment_generator::{
        ENCODABLE_BYTES_PER_BLOB, blob_data_id,
    },
    utils::encode_pubdata_for_4844_blobs,
};

#[test]
fn test_blob_with_max_size() {
    // Test with maximum possible data size (accounting for 31-byte length prefix)
    let data = [1; ENCODABLE_BYTES_PER_BLOB - 31];
    let encoded_data = encode_pubdata_for_4844_blobs(&data);
    assert_eq!(encoded_data.len(), ENCODABLE_BYTES_PER_BLOB);

    let versioned_hash = blob_data_id(&encoded_data);
    let mut expected_hasher = Keccak256::new();
    expected_hasher.update(&encoded_data);
    let versioned_hash_expected = expected_hasher.finalize();

    assert_eq!(versioned_hash, versioned_hash_expected)
}

#[test]
fn test_blob_with_data() {
    // Test with a moderate amount of data (1KB)
    let data = [1; 1024];
    let encoded_data = encode_pubdata_for_4844_blobs(&data);

    let versioned_hash = blob_data_id(&encoded_data);
    let mut expected_hasher = Keccak256::new();
    expected_hasher.update(&encoded_data);
    let versioned_hash_expected = expected_hasher.finalize();

    assert_eq!(versioned_hash, versioned_hash_expected)
}

#[test]
fn test_empty_blob() {
    // Test edge case: empty data should still produce valid commitment
    let data = [];
    let encoded_data = encode_pubdata_for_4844_blobs(&data);

    let versioned_hash = blob_data_id(&encoded_data);
    let mut expected_hasher = Keccak256::new();
    expected_hasher.update(&encoded_data);
    let versioned_hash_expected = expected_hasher.finalize();

    assert_eq!(versioned_hash, versioned_hash_expected)
}
