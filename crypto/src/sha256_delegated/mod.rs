//! SHA-256 with an optional proving-only round delegation.
//!
//! This module is deliberately not used by the standard SHA-256 system
//! function. The Syscoin SLH-DSA verifier uses it to share a block-aligned
//! `PK.seed || zero padding` midstate without changing any other SHA consumer.

#[cfg(all(target_arch = "riscv32", feature = "sha256-round-delegation"))]
mod delegated;
#[cfg(not(all(target_arch = "riscv32", feature = "sha256-round-delegation")))]
mod portable;

#[cfg(all(target_arch = "riscv32", feature = "sha256-round-delegation"))]
use delegated as round_backend;
#[cfg(not(all(target_arch = "riscv32", feature = "sha256-round-delegation")))]
use portable as round_backend;

const BLOCK_BYTES: usize = 64;
const LENGTH_OFFSET: usize = 56;

// SYSCOIN: FIPS 180-4 SHA-256 initial chaining value.
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

// SYSCOIN: FIPS 180-4 SHA-256 round constants. The CSR receives the
// appropriate constant in x12; it does not rely on a circuit-local lookup.
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Number of delegated round requests made for one SHA-256 compression.
pub const DELEGATION_REQUESTS_PER_COMPRESSION: usize = 64;

#[inline(always)]
fn small_sigma0(value: u32) -> u32 {
    value.rotate_right(7) ^ value.rotate_right(18) ^ (value >> 3)
}

#[inline(always)]
fn small_sigma1(value: u32) -> u32 {
    value.rotate_right(17) ^ value.rotate_right(19) ^ (value >> 10)
}

/// Compress one 64-byte block into `state`.
///
/// The rolling schedule and feed-forward addition remain ordinary guest code.
/// On a proving RISC-V guest only each round transition is CSR `0x7cb`, keeping
/// the delegated circuit narrow enough for its fixed trace domain.
#[inline]
pub fn compress_block(state: &mut [u32; 8], block: &[u8; BLOCK_BYTES]) {
    let original_state = *state;
    let mut working_state = original_state;
    let mut rolling_window: [u32; 16] = core::array::from_fn(|index| {
        let offset = index * 4;
        u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ])
    });

    for (round, round_constant) in ROUND_CONSTANTS.into_iter().enumerate() {
        // SYSCOIN: keep the schedule in a 16-word ring. At round `t`, slot
        // `t mod 16` still contains W[t - 16], so expanding in place avoids
        // shifting fifteen words before every delegated round.
        let schedule_index = round & 15;
        let word = if round < 16 {
            rolling_window[schedule_index]
        } else {
            small_sigma1(rolling_window[(schedule_index + 14) & 15])
                .wrapping_add(rolling_window[(schedule_index + 9) & 15])
                .wrapping_add(small_sigma0(rolling_window[(schedule_index + 1) & 15]))
                .wrapping_add(rolling_window[schedule_index])
        };
        rolling_window[schedule_index] = word;
        // SYSCOIN: x11 points directly at this aligned ring-buffer slot, matching the
        // delegated circuit's single indirect schedule-word read.
        round_backend::sha256_round(
            &mut working_state,
            &rolling_window[schedule_index],
            round_constant,
        );
    }

    for ((dst, working), original) in state.iter_mut().zip(working_state).zip(original_state) {
        *dst = working.wrapping_add(original);
    }
}

/// Minimal incremental SHA-256 hasher supporting cheap cloning of a
/// block-aligned midstate.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    total_len: u64,
    #[cfg(test)]
    compression_count: usize,
}

impl Sha256 {
    #[inline]
    pub const fn new() -> Self {
        Self {
            state: IV,
            buffer: [0u8; BLOCK_BYTES],
            buffer_len: 0,
            total_len: 0,
            #[cfg(test)]
            compression_count: 0,
        }
    }

    /// Append bytes to the message.
    pub fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);

        if self.buffer_len != 0 {
            let take = core::cmp::min(BLOCK_BYTES - self.buffer_len, input.len());
            let end = self.buffer_len + take;
            self.buffer[self.buffer_len..end].copy_from_slice(&input[..take]);
            self.buffer_len = end;
            input = &input[take..];
            if self.buffer_len == BLOCK_BYTES {
                self.compress_buffer();
            } else {
                return;
            }
        }

        while let Some((block, rest)) = input.split_first_chunk::<BLOCK_BYTES>() {
            compress_block(&mut self.state, block);
            #[cfg(test)]
            {
                self.compression_count += 1;
            }
            input = rest;
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    /// Finalize and return the digest as canonical big-endian bytes.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > LENGTH_OFFSET {
            self.buffer[self.buffer_len..].fill(0);
            self.compress_buffer();
        }

        self.buffer[self.buffer_len..LENGTH_OFFSET].fill(0);
        self.buffer[LENGTH_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        self.compress_buffer();

        let mut digest = [0u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    #[inline]
    fn compress_buffer(&mut self) {
        compress_block(&mut self.state, &self.buffer);
        self.buffer = [0u8; BLOCK_BYTES];
        self.buffer_len = 0;
        #[cfg(test)]
        {
            self.compression_count += 1;
        }
    }

    #[cfg(test)]
    fn compression_count(&self) -> usize {
        self.compression_count
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn reference(input: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(input).into()
    }

    #[test]
    fn delegated_pointer_abi_is_aligned_and_nonoverlapping() {
        let mut working_state = [0u32; 8];
        let rolling_window = [0u32; 16];
        let state_address = core::ptr::from_mut(&mut working_state).addr();
        assert_eq!(core::mem::size_of_val(&working_state), 8 * 4);
        assert_eq!(core::mem::size_of_val(&rolling_window), 16 * 4);
        assert_eq!(core::mem::align_of_val(&working_state), 4);
        assert_eq!(core::mem::align_of_val(&rolling_window), 4);
        assert_eq!(state_address % 4, 0);
        let state_end = state_address + core::mem::size_of_val(&working_state);

        // SYSCOIN: every round passes one of these exact ring-buffer slots in
        // x11. Check the full set rather than relying only on the array base.
        for word in &rolling_window {
            let word_address = core::ptr::from_ref(word).addr();
            let word_end = word_address + core::mem::size_of_val(word);
            assert_eq!(word_address % 4, 0);
            assert!(state_end <= word_address || word_end <= state_address);
        }
    }

    #[test]
    fn fips_180_known_answer_vectors() {
        let vectors: &[(&[u8], [u8; 32])] = &[
            (
                b"",
                hex_literal::hex!(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
            ),
            (
                b"abc",
                hex_literal::hex!(
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                ),
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                hex_literal::hex!(
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
                ),
            ),
        ];

        for (message, expected) in vectors {
            let mut hasher = Sha256::new();
            hasher.update(message);
            assert_eq!(hasher.finalize(), *expected);
        }
    }

    #[test]
    #[allow(deprecated)]
    fn compression_matches_sha2_for_arbitrary_state_and_block() {
        use sha2::digest::generic_array::GenericArray;

        let mut random = 0xd1b5_4a32_d192_ed03u64;
        for _ in 0..256 {
            let mut next_u32 = || {
                random ^= random >> 12;
                random ^= random << 25;
                random ^= random >> 27;
                (random.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
            };
            let state = core::array::from_fn(|_| next_u32());
            let mut block = [0u8; BLOCK_BYTES];
            for chunk in block.chunks_exact_mut(4) {
                chunk.copy_from_slice(&next_u32().to_be_bytes());
            }

            let mut actual = state;
            compress_block(&mut actual, &block);

            let mut expected = state;
            let reference_block = GenericArray::clone_from_slice(&block);
            sha2::compress256(&mut expected, &[reference_block]);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn boundary_lengths_and_chunkings_match_sha2() {
        const LENGTHS: &[usize] = &[0, 1, 55, 56, 63, 64, 65, 68, 82, 102, 118, 182, 1174];
        for &len in LENGTHS {
            let message: std::vec::Vec<u8> = (0..len)
                .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let expected = reference(&message);
            for chunk_len in [1, 3, 7, 16, 31, 64, 127] {
                let mut hasher = Sha256::new();
                for chunk in message.chunks(chunk_len) {
                    hasher.update(chunk);
                }
                assert_eq!(hasher.finalize(), expected, "len={len}, chunk={chunk_len}");
            }
        }
    }

    #[test]
    fn cloned_block_midstate_matches_naive_prefix_hashing() {
        let mut prefix = [0u8; BLOCK_BYTES];
        prefix[..16].copy_from_slice(&[0xa5; 16]);
        let mut midstate = Sha256::new();
        midstate.update(&prefix);
        assert_eq!(midstate.compression_count(), 1);

        for tail_len in [0, 1, 22, 38, 54, 118, 1110] {
            let tail: std::vec::Vec<u8> = (0..tail_len)
                .map(|index| (index as u8).wrapping_mul(19))
                .collect();
            let mut cloned = midstate.clone();
            cloned.update(&tail);
            let mut full = prefix.to_vec();
            full.extend_from_slice(&tail);
            assert_eq!(cloned.finalize(), reference(&full), "tail={tail_len}");
        }
    }
}
