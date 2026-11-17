# Data Availability Commitment Schemes

ZKsync OS supports multiple Data Availability (DA) commitment schemes to accommodate different deployment scenarios, including Ethereum calldata, compact Syscoin Bitcoin DA, and validium-style external DA. This document provides a comprehensive overview of the implemented DA commitment schemes and their technical details.

## Overview

DA commitment schemes determine how pubdata (the data needed to reconstruct chain state) is committed to and made available for verification. The choice of scheme affects:
- **Cost**: Different schemes have varying costs for data publication
- **Security**: The level of data availability guarantees
- **Compatibility**: Integration with different settlement layers and DA solutions

## Supported DA Commitment Schemes

ZKsync OS implements five distinct DA commitment schemes, defined in [`da_commitment_scheme.rs`](../zk_ee/src/common_structs/da_commitment_scheme.rs):

### 1. None (ID: 0)
**Purpose**: Invalid/uninitialized state

**Implementation**: No-op

**Use Case**: Internal system state only

### 2. EmptyNoDA (ID: 1)
**Purpose**: Validium mode - no data availability guarantees

**Implementation**: [`NopCommitmentGenerator`](../basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/da_commitment_generator/mod.rs)

**Commitment**: Always returns zero hash (`0x000...000`)

**Use Case**:
- Validiums where DA is handled off-chain
- Private chains where data availability is not required
- Reduced fees due to lower pubdata costs

### 3. PubdataKeccak256 (ID: 2)
**Purpose**: Custom DA solutions using keccak256

**Status**: Currently not supported

**Use Case**: Third-party DA layers (Celestia, Avail, etc.)

### 4. BlobsAndPubdataKeccak256 (ID: 3)
**Purpose**: Traditional rollup mode using Ethereum calldata

**Implementation**: [`Keccak256CommitmentGenerator`](../basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/da_commitment_generator/keccak256_commitment_generator.rs)

**Commitment Calculation**:
```
da_commitment = keccak256(
    state_diffs_hash,     // 32 bytes (zero-filled for now)
    pubdata_keccak,       // 32 bytes (keccak256 of full pubdata)
    blob_count,           // 1 byte (always 1 for calldata mode)
    blob_hash            // 32 bytes (zero-filled, ignored on settlement layer)
)
```

**Use Case**:
- Traditional Ethereum rollups using calldata for DA
- Compatible with existing rollup infrastructure
- Provides full data availability guarantees through Ethereum

**Technical Details**:
- Maintains backward compatibility with existing rollup validators
- Uses a "fake" blob structure to maintain consistency with blob-based schemes
- State diffs hash is zero-filled as legacy compatibility requirement

### 5. BlobsZKsyncOS (ID: 4)
**Purpose**: Compact Syscoin Bitcoin DA commitment (the enum ID is retained on the wire)

**Implementation**: [`SyscoinDACommitmentGenerator`](../basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/da_commitment_generator/syscoin_commitment_generator.rs)

**SYSCOIN:** The upstream `BlobCommitmentGenerator` KZG implementation and its callable oracle
remain in-tree unchanged for alignment and reviewability, but scheme ID 4 selects the compact
generator in the Syscoin postimage.

**Key Parameters**:
- **Data-ID chunk size**: 2 MiB
- **Maximum chunks supported**: 32
- **Total capacity**: 64 MiB, including the 31-byte length prefix

**Data-ID Process**:

1. **Length Encoding**: The first 31 bytes encode data length as `[length_be_8_bytes, 23_zeros]`
2. **Data Chunking**: The prefixed bytes are split into 2 MiB chunks
3. **Guest Computation**: The proving guest computes a 32-byte Blake2s ID for each chunk directly

**Commitment Calculation**:
```
For each chunk:
  data_id = blake2s(chunk)

final_commitment = keccak256(all_data_ids)
```

**Use Case**:
- Syscoin's compact Bitcoin DA publication path
- A proving statement that binds the published bytes to the exact data IDs committed through
  Gateway and L1

This DA commitment path is independent of EVM Cancun compatibility. The EIP-4844 transaction
format and point-evaluation precompile remain available to contracts.

## DA Commitment Generation Process

The DA commitment generation follows a consistent pattern across all schemes:

### 1. Initialization
```rust
let generator = da_commitment_generator_from_scheme(scheme, allocator)?;
```

### 2. Data Accumulation
```rust
impl WriteBytes for Generator {
    fn write(&mut self, buf: &[u8]) {
        // Accumulate pubdata chunks
    }
}
```

### 3. Finalization
```rust
impl DACommitmentGenerator for Generator {
    fn finalize(&mut self) -> Bytes32 {
        // Generate final commitment
    }
}
```

## Related Documentation
- [L1 Integration](./l1_integration.md) - Overall settlement layer integration
- [System Hooks](./system_hooks.md) - L1 messaging and pubdata generation
- [Transaction Processing](./bootloader/transaction_processing.md) - Pubdata considerations in transaction validation

## Implementation Files
- **Core Types**: `zk_ee/src/common_structs/da_commitment_scheme.rs`
- **Generators**: `basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/da_commitment_generator/`
- **Blob Implementation**: `basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/da_commitment_generator/blob_commitment_generator/`
- **Testing**: unit tests beside the blob commitment generator
