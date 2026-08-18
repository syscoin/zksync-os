use crate::cost_constants::{
    SLH_DSA_SHA2_128_24_VERIFY_COST_ERGS, SLH_DSA_SHA2_128_24_VERIFY_NATIVE_COST,
};
use crypto::sha256::{compress256, digest::core_api::Block, Digest, Sha256, Sha256VarCore};
use zk_ee::common_traits::TryExtend;
use zk_ee::out_of_return_memory;
use zk_ee::system::{
    base_system_functions::{SlhDsaSha212824VerifyErrors, SystemFunction},
    errors::subsystem::SubsystemError,
    Computational, Resources,
};

// SYSCOIN: `SLH-DSA-SHA2-128-24` is the NIST SP 800-230 IPD limited-signature
// parameter set (n=16, h=22, d=1, a=24, k=6, w=4). It instantiates the FIPS
// 205 external SLH-DSA algorithms and SHA2 address/hash formats, but it is not
// one of the named parameter sets in the final FIPS 205 publication.
const N: usize = 16;
const SIGNATURE_LEN: usize = 3856;
const INPUT_LEN: usize = 32 + 32 + 32 + SIGNATURE_LEN;
const FORS_TREES: usize = 6;
const FORS_HEIGHT: usize = 24;
const WOTS_LEN: usize = 68;
const MERKLE_HEIGHT: usize = 22;
const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_LENGTH_OFFSET: usize = 56;

// FIPS 180-4 section 5.3.3 SHA-256 initial hash value. Keeping the chaining
// value explicit lets F/H/T start from the shared, block-aligned seed state.
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

pub struct SlhDsaSha212824VerifyImpl;

impl<R: Resources> SystemFunction<R, SlhDsaSha212824VerifyErrors> for SlhDsaSha212824VerifyImpl {
    fn execute<D: TryExtend<u8> + ?Sized, A: core::alloc::Allocator + Clone>(
        src: &[u8],
        dst: &mut D,
        resources: &mut R,
        _: A,
    ) -> Result<(), SubsystemError<SlhDsaSha212824VerifyErrors>> {
        // SYSCOIN: isolate cycle accounting for the complete 0x101 operation,
        // including its fixed resource charge.
        Ok(cycle_marker::wrap_with_resources!(
            "slh_dsa_sha2_128_24_verify",
            resources,
            { slh_dsa_sha2_128_24_verify_inner(src, dst, resources) }
        )?)
    }
}

fn slh_dsa_sha2_128_24_verify_inner<D: TryExtend<u8> + ?Sized, R: Resources>(
    src: &[u8],
    dst: &mut D,
    resources: &mut R,
) -> Result<(), SubsystemError<SlhDsaSha212824VerifyErrors>> {
    let native =
        <R as Resources>::Native::from_computational(SLH_DSA_SHA2_128_24_VERIFY_NATIVE_COST);
    // SYSCOIN: retain fixed charging before parsing so malformed and valid
    // inputs have the same consensus resource cost.
    resources.charge(&R::from_ergs_and_native(
        SLH_DSA_SHA2_128_24_VERIFY_COST_ERGS,
        native,
    ))?;

    let mut output = [0u8; 32];
    output[31] = u8::from(slh_dsa_sha2_128_24_verify(src));
    dst.try_extend(output)
        .map_err(|_| out_of_return_memory!())?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompressedAddress {
    kind: u8,
    keypair: u32,
    chain_or_height: u32,
    hash_or_index: u32,
}

impl CompressedAddress {
    const fn new(kind: u8, keypair: u32) -> Self {
        Self {
            kind,
            keypair,
            chain_or_height: 0,
            hash_or_index: 0,
        }
    }

    const fn with_chain_or_height(mut self, value: u32) -> Self {
        self.chain_or_height = value;
        self
    }

    const fn with_hash_or_index(mut self, value: u32) -> Self {
        self.hash_or_index = value;
        self
    }

    // SYSCOIN: FIPS 205 section 11.2 SHA2 simple compressed ADRS, used by the
    // SP 800-230 parameter set. Layer and tree are zero for this d=1 instance.
    fn to_bytes(self) -> [u8; 22] {
        let mut result = [0u8; 22];
        result[9] = self.kind;
        result[10..14].copy_from_slice(&self.keypair.to_be_bytes());
        result[14..18].copy_from_slice(&self.chain_or_height.to_be_bytes());
        result[18..22].copy_from_slice(&self.hash_or_index.to_be_bytes());
        result
    }
}

trait SlhHashing {
    fn new(seed: &[u8; N]) -> Self;
    fn message_digest(
        &mut self,
        root: &[u8; N],
        message: &[u8; 32],
        randomness: &[u8; N],
    ) -> [u8; 32];
    fn hash_n<const M: usize>(
        &mut self,
        address: CompressedAddress,
        parts: &[[u8; N]; M],
    ) -> [u8; N];
}

struct SlhSha256 {
    seed: [u8; N],
    seed_state: [u32; 8],
    #[cfg(test)]
    compression_count: usize,
}

impl SlhHashing for SlhSha256 {
    fn new(seed: &[u8; N]) -> Self {
        // SYSCOIN: every F/H/T hash begins with this exact 64-byte block.
        // Hash it once and reuse the block-aligned state for each invocation.
        let mut seed_block = [0u8; SHA256_BLOCK_BYTES];
        seed_block[..N].copy_from_slice(seed);
        let mut seed_state = SHA256_IV;
        compress_block(&mut seed_state, &seed_block);
        Self {
            seed: *seed,
            seed_state,
            #[cfg(test)]
            compression_count: 1,
        }
    }

    fn message_digest(
        &mut self,
        root: &[u8; N],
        message: &[u8; 32],
        randomness: &[u8; N],
    ) -> [u8; 32] {
        // SYSCOIN: external SLH-DSA with an empty context hashes
        // `R || PK.seed || PK.root || 0x00 || 0x00 || M`.
        let mut first = Sha256::new();
        first.update(randomness);
        first.update(&self.seed);
        first.update(root);
        first.update(&[0u8; 2]);
        first.update(message);
        let first = first.finalize();

        let mut second = Sha256::new();
        second.update(randomness);
        second.update(&self.seed);
        second.update(&first);
        second.update(&[0u8; 4]);
        #[cfg(test)]
        {
            // Both the 82-byte inner hash and 68-byte MGF1 block use two
            // compressions.
            self.compression_count += 4;
        }
        second.finalize().into()
    }

    fn hash_n<const M: usize>(
        &mut self,
        address: CompressedAddress,
        parts: &[[u8; N]; M],
    ) -> [u8; N] {
        let mut state = self.seed_state;
        let mut block = [0u8; SHA256_BLOCK_BYTES];
        let address = address.to_bytes();

        // A worst-case verification has 207 M=1 hashes and 166 M=2 hashes;
        // each complete post-seed input and SHA-256 padding fits in one block.
        // Build those 373 tails directly, avoiding incremental bookkeeping.
        if M <= 2 {
            block[..address.len()].copy_from_slice(&address);
            let mut offset = address.len();
            for part in parts {
                block[offset..offset + N].copy_from_slice(part);
                offset += N;
            }
            block[offset] = 0x80;
            let bit_len = ((SHA256_BLOCK_BYTES + offset) as u64).wrapping_mul(8);
            block[SHA256_LENGTH_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
            compress_block(&mut state, &block);
        } else {
            // The two aggregation hashes (M=6 and M=68) use the same raw
            // midstate, with a compact streaming tail for their extra blocks.
            let mut block_len = 0;
            update_tail(&mut state, &mut block, &mut block_len, &address);
            for part in parts {
                update_tail(&mut state, &mut block, &mut block_len, part);
            }

            block[block_len] = 0x80;
            block_len += 1;
            if block_len > SHA256_LENGTH_OFFSET {
                block[block_len..].fill(0);
                compress_block(&mut state, &block);
                block = [0u8; SHA256_BLOCK_BYTES];
            } else {
                block[block_len..SHA256_LENGTH_OFFSET].fill(0);
            }
            let message_len = SHA256_BLOCK_BYTES + address.len() + M * N;
            block[SHA256_LENGTH_OFFSET..]
                .copy_from_slice(&((message_len as u64).wrapping_mul(8)).to_be_bytes());
            compress_block(&mut state, &block);
        }

        let mut result = [0u8; N];
        for (chunk, word) in result.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        #[cfg(test)]
        {
            // The shared prefix compression was counted once in `new`.
            self.compression_count += sha256_compressions(64 + 22 + M * N) - 1;
        }
        result
    }
}

#[inline(always)]
fn compress_block(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_BYTES]) {
    let block: Block<Sha256VarCore> = (*block).into();
    compress256(state, core::slice::from_ref(&block));
}

#[inline(always)]
fn update_tail(
    state: &mut [u32; 8],
    block: &mut [u8; SHA256_BLOCK_BYTES],
    block_len: &mut usize,
    mut input: &[u8],
) {
    while !input.is_empty() {
        let take = core::cmp::min(SHA256_BLOCK_BYTES - *block_len, input.len());
        let end = *block_len + take;
        block[*block_len..end].copy_from_slice(&input[..take]);
        *block_len = end;
        input = &input[take..];
        if *block_len == SHA256_BLOCK_BYTES {
            compress_block(state, block);
            *block = [0u8; SHA256_BLOCK_BYTES];
            *block_len = 0;
        }
    }
}

fn slh_dsa_sha2_128_24_verify(src: &[u8]) -> bool {
    let Some((seed, root, message, signature)) = parse_input(src) else {
        return false;
    };
    let mut hashing = SlhSha256::new(&seed);
    verify_parsed(&root, message, signature, &mut hashing).unwrap_or(false)
}

fn parse_input(src: &[u8]) -> Option<([u8; N], [u8; N], &[u8; 32], &[u8])> {
    if src.len() != INPUT_LEN {
        return None;
    }
    let seed = canonical_n(src.get(0..32)?)?;
    let root = canonical_n(src.get(32..64)?)?;
    let message = src.get(64..96)?.try_into().ok()?;
    let signature = src.get(96..)?;
    Some((seed, root, message, signature))
}

fn verify_parsed<H: SlhHashing>(
    root: &[u8; N],
    message: &[u8; 32],
    sig: &[u8],
    hashing: &mut H,
) -> Option<bool> {
    let randomness = n_at(sig, 0)?;
    let digest_word = hashing.message_digest(root, message, &randomness);
    let leaf_idx = (((digest_word[18] as u32) & 0x3f) << 16)
        | ((digest_word[19] as u32) << 8)
        | digest_word[20] as u32;

    let fors_base = CompressedAddress::new(3, leaf_idx);
    let wots_base = CompressedAddress::new(0, leaf_idx);
    let mut fors_roots = [[0u8; N]; FORS_TREES];

    for (t, fors_root) in fors_roots.iter_mut().enumerate() {
        let md_t_offset = t * 3;
        let md_t = ((digest_word[md_t_offset] as u32) << 16)
            | ((digest_word[md_t_offset + 1] as u32) << 8)
            | digest_word[md_t_offset + 2] as u32;
        let tree_offset = N + t * (N + FORS_HEIGHT * N);
        let sk = n_at(sig, tree_offset)?;
        let mut node = hashing.hash_n(
            fors_base.with_hash_or_index(((t as u32) << 24) | md_t),
            &[sk],
        );
        let mut path_idx = md_t;

        for j in 0..FORS_HEIGHT {
            let sibling = n_at(sig, tree_offset + N + j * N)?;
            let parent_idx = path_idx >> 1;
            let global_y = ((t as u32) << (23 - j)) | parent_idx;
            let address = fors_base
                .with_chain_or_height((j + 1) as u32)
                .with_hash_or_index(global_y);
            node = if path_idx & 1 == 0 {
                hashing.hash_n(address, &[node, sibling])
            } else {
                hashing.hash_n(address, &[sibling, node])
            };
            path_idx = parent_idx;
        }
        *fors_root = node;
    }

    let current_node = hashing.hash_n(CompressedAddress::new(4, leaf_idx), &fors_roots);
    let wots_ptr = N + FORS_TREES * (N + FORS_HEIGHT * N);
    let mut csum = 0u32;
    let mut wots_chains = [[0u8; N]; WOTS_LEN];

    for (i, wots_chain) in wots_chains.iter_mut().take(64).enumerate() {
        let digit = base4_digit(&current_node, i);
        csum += 3 - digit as u32;
        let mut value = n_at(sig, wots_ptr + i * N)?;
        let chain_base = wots_base.with_chain_or_height(i as u32);
        for s in 0..(3 - digit) {
            value = hashing.hash_n(chain_base.with_hash_or_index((digit + s) as u32), &[value]);
        }
        *wots_chain = value;
    }

    for j in 0..4 {
        let digit = ((csum >> (6 - 2 * j)) & 3) as u8;
        let i = 64 + j;
        let mut value = n_at(sig, wots_ptr + i * N)?;
        let chain_base = wots_base.with_chain_or_height(i as u32);
        for s in 0..(3 - digit) {
            value = hashing.hash_n(chain_base.with_hash_or_index((digit + s) as u32), &[value]);
        }
        wots_chains[i] = value;
    }

    let wots_pk = hashing.hash_n(CompressedAddress::new(1, leaf_idx), &wots_chains);
    let auth_ptr = wots_ptr + WOTS_LEN * N;
    let mut merkle_node = wots_pk;
    let mut merkle_idx = leaf_idx;

    for height in 0..MERKLE_HEIGHT {
        let sibling = n_at(sig, auth_ptr + height * N)?;
        let parent_idx = merkle_idx >> 1;
        let address = CompressedAddress::new(2, 0)
            .with_chain_or_height((height + 1) as u32)
            .with_hash_or_index(parent_idx);
        merkle_node = if merkle_idx & 1 == 0 {
            hashing.hash_n(address, &[merkle_node, sibling])
        } else {
            hashing.hash_n(address, &[sibling, merkle_node])
        };
        merkle_idx = parent_idx;
    }

    Some(merkle_node == *root)
}

fn canonical_n(word: &[u8]) -> Option<[u8; N]> {
    if word.len() != 32 || word[N..].iter().any(|byte| *byte != 0) {
        return None;
    }
    word.get(..N)?.try_into().ok()
}

fn n_at(src: &[u8], offset: usize) -> Option<[u8; N]> {
    src.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

#[cfg(test)]
const fn sha256_compressions(message_len: usize) -> usize {
    (message_len + 9).div_ceil(64)
}

#[cfg(test)]
struct ReferenceSlhSha256 {
    seed: [u8; N],
}

#[cfg(test)]
impl SlhHashing for ReferenceSlhSha256 {
    fn new(seed: &[u8; N]) -> Self {
        Self { seed: *seed }
    }

    fn message_digest(
        &mut self,
        root: &[u8; N],
        message: &[u8; 32],
        randomness: &[u8; N],
    ) -> [u8; 32] {
        use crypto::sha256::Digest;

        let mut first = crypto::sha256::Sha256::new();
        first.update(randomness);
        first.update(self.seed);
        first.update(root);
        first.update([0u8; 2]);
        first.update(message);
        let first = first.finalize();

        let mut second = crypto::sha256::Sha256::new();
        second.update(randomness);
        second.update(self.seed);
        second.update(first);
        second.update([0u8; 4]);
        second.finalize().into()
    }

    fn hash_n<const M: usize>(
        &mut self,
        address: CompressedAddress,
        parts: &[[u8; N]; M],
    ) -> [u8; N] {
        use crypto::sha256::Digest;

        let mut hasher = crypto::sha256::Sha256::new();
        hasher.update(self.seed);
        hasher.update([0u8; 48]);
        hasher.update(address.to_bytes());
        for part in parts {
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut result = [0u8; N];
        result.copy_from_slice(&digest[..N]);
        result
    }
}

#[cfg(test)]
fn verify_with_reference_sha256(src: &[u8]) -> bool {
    let Some((seed, root, message, signature)) = parse_input(src) else {
        return false;
    };
    let mut hashing = ReferenceSlhSha256::new(&seed);
    verify_parsed(&root, message, signature, &mut hashing).unwrap_or(false)
}

#[cfg(test)]
fn verify_with_compression_count(src: &[u8]) -> (bool, usize) {
    let Some((seed, root, message, signature)) = parse_input(src) else {
        return (false, 0);
    };
    let mut hashing = SlhSha256::new(&seed);
    let result = verify_parsed(&root, message, signature, &mut hashing).unwrap_or(false);
    (result, hashing.compression_count)
}

fn base4_digit(value: &[u8; N], index: usize) -> u8 {
    (value[index / 4] >> (6 - 2 * (index % 4))) & 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::Global;
    use zk_ee::reference_implementations::{BaseResources, DecreasingNative};
    use zk_ee::system::{Resource, SystemFunction};

    const PK_SEED: [u8; 32] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const PK_ROOT: [u8; 32] = [
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const MESSAGE: [u8; 32] = [0x33; 32];
    // SYSCOIN: legacy acceptance-vector fields copied from
    // `zksync-os-server/contracts/test/vectors/slh_dsa_sha2_128_24_kat.json`,
    // introduced by server commit 6b43ab88a6e3851f45529e89d23670d0fc0c324b.
    // SHA-256(original JSON at that commit) =
    // 859639cf4c2c1d508a95556923791610e9c1f957438703526928cdf07674bdb9;
    // SHA-256(current provenance-annotated JSON) =
    // ba33ddf2addd6393e727b2c299e10ec2b551bfaf3dc7fe23373e7df00dfa6385;
    // SHA-256(signature bytes) =
    // 39aa2b5f6544bd143881b07920be7f030d4018d82f95b32d38f366d96102b02c.
    // The original fixture does not include the signing seeds or command, so it
    // is not a byte-reproducible NIST/ACVP KAT. The server conformance corpus
    // independently validates it with pinned pq-code-package/slhdsa-c and keeps
    // a separately reproducible SP 800-230 IPD vector. The upstream Verity/Lean
    // work is model-to-byte-spec under documented axioms; it is not a vector
    // oracle or a proof of this Rust or GPU implementation.
    const KAT_PK_SEED: [u8; 32] = [
        0x9a, 0xf9, 0xa6, 0xd9, 0x86, 0xbc, 0x74, 0x50, 0xf9, 0x9c, 0x34, 0xe8, 0xac, 0xa4, 0x53,
        0xc8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const KAT_PK_ROOT: [u8; 32] = [
        0x37, 0xb5, 0xd9, 0x7a, 0xfc, 0xfb, 0xd8, 0x11, 0x8e, 0x75, 0xe5, 0x0a, 0xba, 0x48, 0x0a,
        0x9e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const KAT_MESSAGE: [u8; 32] = [0xaa; 32];
    const KAT_SIGNATURE_HEX: &str = "bd60ba6ad8d703a4d8d790c2e9e11d2bb18b3843cae896c3df7f8e2e85f56b5cffa2bca00b4bc8a79988fe182d07a5b27faaa62a1619a8ecd8519bf3c17efd475e422b022fd47396394cf85d0ccfe5c57cd2d9af5cd942fb3716b05f8d8d88645dca3067ce75013552fb5ea31d2abfbd475800565986a6de7ceae379e30cb890007eb5bf5501bce8bfe0cd5f8415f5d3292c7829f2ee335a37067ea08149520e7ec419351f54d248d2f913eb57e17de65cb4fb7d34af2ec5460f56e26ed6467f09d30e79e055aa978d12174d6903abb26ebb8d39eb934c159b1cd4ee20cdd5ff650cf796344e81d604074bfa3a538987269f4b546516d8dd38eb466cb7363cdf7190f24c4a441b7626398126f995c4376fb0c0888bd47a056f468be7c6502eeb066f5c0bd52bb66f671ac3469e2e5468da21d233d5886fcd421167f1bf0d4b981b09fe2b61371806baee850c522ce39bdc6d96e55ace1cf63d14cf9c24ea0945bc83b648554b7cfe5222f5796f24ba0be1a58b72e33977eea59ad395564537c08eb69799deee206e681c6dcc8dfaf079fa4826275eda22eae179c8aaf7dbf7c8def911138af9be89bdbd71b74321e53015ffeab0b8fbb7e2c313d151287a9c8866b517adbf999b17dbaeef40500bf7fe1d8c42be48ce977be16f243f09051eb0d82fd3fbe09b7af05fa5602521f662c92ae914bbfe1c5aac518941d0e91aa33a6677ca974444bff6a03551c3a789f5d74e6fda5a4b9aa555c5f88bfa529bc9791c8072427c01aae4469d2f09477e29d8c51d7132a0b745ffd49c0ff4db57fd97a10559e899106043c2699ba78672f37ae69cec718c2f7942f0f2f30a9c3ba2b16f4c2f468f0c833f2d54527825f7b8582c06541b9c9a8a2f7d4e4ed94abc1b649906364cf35e1f9df2259acc04684e37702e61c91830eb3ff5536fced3d4726fdc229abbd501b75e11117c02e6b5b4c9fcbc74f1744aecf05d9f649ded057fc41a961aac0192da5d11c2551a29c0a338deb32d66609b28bd3887f378cc3043014f72923c3081b1a647a018fc7fc7cc78f1b5d624ab93672548c7e5d0e8c34a43c93ab7203f3344e3c82e96b2bdae6bddda092c5666c0022046c60aebf106a50467442951720ad0398c8a4836d0aedc09a69a68d770343c44c78c3eca8d11a01bbcbbfb762ba6cffd611f0d6ff7c698b1781569d32384bc1549111b8651bd721206aa1472a070f6508dee001d571d6a6ea60e8e63da0395a7905c98cf2ffc5c9cb3ef67c70aaa673d73c630dea687026f159fe097dbb6f887335f0b4d994fbe6e7e1704a49dd0d69ea99a7e67e601dda36f85ef23c58baa120da64213c5c614f7af0dc53d0ea569caf390ae417f47b249513e60a33dceb2a8b5919e98b4c80ff55e2a0fc2ead229be3d44cbc1a5ece6fad9d9c247b5110eb6fd2ce68bc3c650e1d09a17f4592e7ee2df1229b63e4ce4727a30c75b85c96c1c8e38ef703c27de0dd8c02ef8b3732158a2b6875b2732628722ab9d19dbec51540a2f8e5024c24ae7189b7d6049b2377e04799110d24575b558397aa97384403075d2b0eae09bac1fe4a6d4ba4b3f7ec5f7c063abe470f700a06e78a8470ab530302a7ed12e4fc932d5dd6ee1abf95fe381047df22c558e08318e24e811f74627108bf70508ac7c47d505603ed61cc5700fd4f640c3afa4fe995f5264da45231b6c6414991fff34fb73ae53d38a53f29b6938cb437cdb072d43209656f7a1fbb59a5ff88920897ff8d07a3ec76c2d3111ba0d84dc87d7dd6f1932a6331d925f80987a8f669c92076a2013e76e99380e75817e58ee78775a3ad6b21bad068cd679f59b28841af61b73f08abd6e72d281caf33249add798f65aa135cfdf9ef768f9b747336bbed0d3c892e3c729aee71455d0225364928aa98782cef3bab3d952d0f7a33606f25926ff24e098ad83829983a87a876e0fe886276c6f0d8bff73ff7520b6a817783839f132ccf12f14d2d06eecdababd61df5995b43ae33596a240c01c2cd7021df2f8facfec23471caa6ab251c715f2bd6a0d46a01a408a86c6dd0a2ecfdf61fa85574a17c83927e6eefa8780fcd8028af81db45de22be3fe941c7d97e1266034a27405d6df8c6e9b8c59bccfb58f8964f6225c370c68d19541a58723fcc2e3870c3143f289e864bb5eef0f47545607f90260506b8d4d763d69e4fcb7b51727983a5ba1d0313db7235b8e8b1603acfc006b291b651cf04a9d4841876e43fc584271d7a17d2f6ca45314c8f132504ce2fcb60ded5ef3a49ef281811e913c2d25684e2c275477128abc33e4f66800f3dc8341a64065f4024bd925471e1e799a68bf47a30516fc7b6de77c8236097b00d2cce087338e4c5d8e0a64decda943883566756b174e9d2740c69d2bcfa20823544737aaf8831cc9bbe53a9ef3e44937887ca706fcf525629d8ec5e3df37910ff1432e212b17a35cb4bf0e19c45203338550881d5cd2ece93c995b7ec3723fca0d9bb900062c5957b482d2de1612139ff5ac5ea7e79f5a3be93be60ba1448ebb5d10f5f8444312d87727aa4238778233dbefe57c70d7d3de241c7551ba0f1164e663f2cde0b9d8e903d2b41faea73fd94beccc00550b1d2511fad53bab56ac708124b17d4724fc8fc555d14e3e5ab1bfad50c152a8c97e4b68256d97e4f6b1be5871a18f4fecd9384c1cd802a51f14b35aa4486312ef4fb76c445c37885cfaac95b382ffb1098ed88ac4b23ba9b3b88865601793204b0160d6e7c3ffdb6240fbb773f10a6aa9c5df41c8a7bbdaa3b80c6f50c65d52da73b97e6c05b72d179f498063b69e5a05a52dfd7b96ca1241e335d74e83f18b642cd7b9a81a735cd0ac99c7952e0bbaf9d830e9d4a67b75b77033c2b566bb076d1efecfc2d060b6784f2cc2969cbd5387e3500d9fba731d983985c855954f19833312c265167b410f72751f5f89624c59238db5b727f03d84ec0e17da4e55b79aff564d3ba7bb47a0554a14596267ba089469de5579b369b5379e6229c4fd11cf156929d09d3cab60d528d9f778987b4b2cc4ead8978f47776712f7ce1779bb665673d72435904d02a1b789b4c174cf0561a21174b7442cb561d898eca4fd88b23be11b14e073a8e6a0567681b409e9ae0efdb6faa991262f5a5294b9a95f08ead7d9089e6fc47a45151234e03ffc909cdfea4754be389288971d4c1d50c9c52eea09f53c85666a107a4237d3d4e9c5dea8abbf167609f6fdd196085709b0afbb892e676d5a1094c6519795661b24f07d51e05ed120ae5a521cf3cd2148cde417a0f62458b987f426ae72979fe0983a2bab19b88f56681f2209a7efcfe539ad1168177784ba98e90946fbe8857ef7f2d8bd5874db0a9bdbce342157037e821e446f8824a37c6c3306d20776bd94197d8ded2611a7ada59bec4886b4a0176c6110f4dfec7922b60b4d40ea242aa9e255a286256c68185abcb65f40f419a346a281d3910d5e922c67938c84bb36ddb2196fec2a3767f7ebeaa090cf1fbfa9d20ec9c79b7d08b92f89676dd198a340dd4744fc0b81f22bfba88ac50fe1256ebcc63e8c13d154dd139d90730d48cc36a6d9cbbf65b371f8595ef4b40906a152aaf8c0e7e58b55267fccb68bc7e637a4934b1fcee678ede09dfcad3ed09a517c7b30b03092998961f963a94ebccd22f63b76c4ed3932ee6e82746be615c90a2b86dfb485e731ec2c2379d6ecdfa0fa6a5b5a960e70543806bdd61e50e9fd1a5612fecd96521272877ea8ff40f2877208e56136e766e45c741e57ccc884595c6a33c5dd7208bdc28f4d1f04a23f30748f19949a172176fa66fcc06fb25cfacc80f8fcc96edf0c694fcf4826458123056454d3427dad2a10ac0dcf316d1605c6360b1b57fa60d9ed658634e51d7cda78e8db3ceac5e6f85060beea2c5f3b89106e3f3f67b4347cc8db1b1a16ea09b68ddf092acdedebee9f87facbe336307e9c337c0421bf90e785310749e3f3af14b78c7443cf24ed71b402c7d5c06810e27ea46afeb0b8b7aff4fc75a586eddee5e4abcf6debb94059ee63a1cd79d448ca8a6dad551c1e76475cb316801637c66e880ff5ef392a204cf9bf4344acb1789fea57ee2495acff462590f11823ab8b8a07dd44bcefc4fedcd9ce31bd9decab3fabe9f158c64208e88112b8cdc64a58f19464ad42409e22ae57a290338dc78fd9e967ae4c8827f1a21c0a4b999128b90b572b554976f4b161642d7db971d7ec929b3ac26588064ef713a7473caec298e6498f8c4aaf2feb5c7b14a9f9304b1fdb269c3bb330443ca5218806874ea30f491d8fc636fc92c66228164aeecd01b90bd81d3a9687a3e09ec0aeeecd6d69fbead98e3a1edcd122e0694f8fec3dea3b541692de6bf11093af4a9c06ef5f16fa8ceec7b598ed9ccd2725a28bc2522ca9a69f00a9b421febffd13f06d80f3a0f0abf684df6e4983f634414cce72fd48404ab338050139ab09a96d7a69e8f974dd174f9ecd504de8e8a8736bc7ac07a94709ee936f96d9069973e5a4cbb4ebfb9bbe2907f1be9bf5bb78bb3178b2575adb5dfcd8a5869385f6ad28ab0fc71a21fc3a0cca256a08ebce24b64169d7a965f63a9f3fcc31495a222ccd403870892d10387fe1f80b99a9fb5133f5525cd5bdbc43c2583d3948fcdb2e03169313ea3d8f5bcfb0bdc0916364aea49ad85e161d9a347a38a18ff19bfea46d3e33043ea5aaaa8c83fab7c9501be1607905377b5f6ecddf52d5fb868d37037626ed29cf38102e55115a62a3846a5959a79ec377bafabeaa346df0dada87e0dd4a7ea1e42d52e96bf23a1cc78044d854be0f16f60f1c6f1cabce663ace2d2d55632d350431be8693ba3e7f7c48acec5c5f230c2cf72bf9345cbdac2c2005b74a606c061b02bb65c5213e24f2b0abf9002a75de87b6191c5cb5f20377561d8fb75467757d542c0f346703be2aa607faf6ceae05be89be4d960fc00c0f087bb9c8725b65b2d3d53b99a09c2e1ce8addf2a9f1451a635cdf1cf3954367034d16e5ab95cf879e96742e83f5bde5836cc7c2f03ef9ae15789e69c98bcb6be92b372b939ec6c8421b0b2388d6fac620e2eaadca554bb2b7ad6417e20d11c786d8cdd60c301b86786c41919319a190e8c438c56dc2ddd49474db262f5c47f7306a7892b2d8632b3f272014f4748c59ceebede6ee33ec5a4d74c76a2c603e11f0cb906fe6d3aba6a022f7f407e8f62ae332815d3ed06f5cff8e86bc373b0cc177aa7e4a3b67995ceb34041218d275bd853f2e0fe5c5ad6653e8a866741a61928899306402ffc56be940857ae7a548ea6a46f8e805bba3fa311c97fbc660b23e1b81ebc6f62250ae79a55bd222db33dad924726d61ba56c898394d2953569316c2b9ce65b52b3131f2c7b99db680896d3277e2078e93a26106c07554054a46278f38f84b0a5959897b003bbb23df819";

    fn kat_input() -> Vec<u8> {
        let signature = hex::decode(KAT_SIGNATURE_HEX).expect("valid hex fixture");
        assert_eq!(signature.len(), SIGNATURE_LEN);
        let mut input = Vec::with_capacity(INPUT_LEN);
        input.extend_from_slice(&KAT_PK_SEED);
        input.extend_from_slice(&KAT_PK_ROOT);
        input.extend_from_slice(&KAT_MESSAGE);
        input.extend_from_slice(&signature);
        input
    }

    fn execute(input: &[u8]) -> Vec<u8> {
        let mut dst = vec![];
        let mut resources = BaseResources::<DecreasingNative>::FORMAL_INFINITE;
        SlhDsaSha212824VerifyImpl::execute(input, &mut dst, &mut resources, Global)
            .expect("precompile execution");
        dst
    }

    #[test]
    fn valid_known_answer_vector_returns_one() {
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(execute(&kat_input()), expected);
    }

    #[test]
    fn malformed_input_returns_zero() {
        assert_eq!(execute(&[0u8; 3]), [0u8; 32]);
    }

    #[test]
    fn noncanonical_public_key_returns_zero() {
        let mut input = vec![];
        input.extend_from_slice(&PK_SEED);
        input.extend_from_slice(&PK_ROOT);
        input.extend_from_slice(&MESSAGE);
        input.extend_from_slice(&[0u8; SIGNATURE_LEN]);
        input[31] = 1;
        assert_eq!(execute(&input), [0u8; 32]);
    }

    #[test]
    fn zero_signature_returns_zero() {
        let mut input = vec![];
        input.extend_from_slice(&PK_SEED);
        input.extend_from_slice(&PK_ROOT);
        input.extend_from_slice(&MESSAGE);
        input.extend_from_slice(&[0u8; SIGNATURE_LEN]);
        assert_eq!(execute(&input), [0u8; 32]);
    }

    #[test]
    fn typed_addresses_match_legacy_u256_encoding() {
        fn legacy(address: CompressedAddress) -> [u8; 22] {
            use ruint::aliases::U256;

            let encoded: U256 = (U256::from(address.kind) << 176)
                | (U256::from(address.keypair) << 144)
                | (U256::from(address.chain_or_height) << 112)
                | (U256::from(address.hash_or_index) << 80);
            let encoded = encoded.to_be_bytes::<32>();
            let mut result = [0u8; 22];
            result.copy_from_slice(&encoded[..22]);
            result
        }

        for kind in 0..=4 {
            for (keypair, chain_or_height, hash_or_index) in [
                (0, 0, 0),
                (0x0037_d65d, 1, 0x0001_0203),
                (u32::MAX, u32::MAX, u32::MAX),
            ] {
                let address = CompressedAddress::new(kind, keypair)
                    .with_chain_or_height(chain_or_height)
                    .with_hash_or_index(hash_or_index);
                assert_eq!(address.to_bytes(), legacy(address));
            }
        }
    }

    #[test]
    fn optimized_kat_has_exact_compression_count() {
        let (valid, compressions) = verify_with_compression_count(&kat_input());
        assert!(valid);
        assert_eq!(compressions, 296);

        let max_wots_steps = (0usize..=192)
            .map(|checksum| {
                let digit_sum = [6, 4, 2, 0]
                    .into_iter()
                    .map(|shift| (checksum >> shift) & 3)
                    .sum::<usize>();
                checksum + 12 - digit_sum
            })
            .max();
        assert_eq!(max_wots_steps, Some(201));
        let worst_case_compressions = 197 + max_wots_steps.unwrap_or_default();
        assert_eq!(worst_case_compressions, 398);
    }

    #[test]
    fn raw_midstate_matches_digest_for_every_used_arity_and_extreme_address() {
        fn next_byte(random: &mut u64) -> u8 {
            *random ^= *random >> 12;
            *random ^= *random << 25;
            *random ^= *random >> 27;
            random.wrapping_mul(0x2545_f491_4f6c_dd1d) as u8
        }

        fn check<const M: usize>(
            optimized: &mut SlhSha256,
            reference: &mut ReferenceSlhSha256,
            address: CompressedAddress,
            random: &mut u64,
        ) {
            let parts: [[u8; N]; M] =
                core::array::from_fn(|_| core::array::from_fn(|_| next_byte(random)));
            assert_eq!(
                optimized.hash_n(address, &parts),
                reference.hash_n(address, &parts),
                "raw SHA-256 mismatch for M={M}, address={address:?}"
            );
        }

        let mut random = 0x510e_527f_9b05_688cu64;
        for _ in 0..64 {
            let seed = core::array::from_fn(|_| next_byte(&mut random));
            let mut optimized = SlhSha256::new(&seed);
            let mut reference = ReferenceSlhSha256::new(&seed);
            let random_address = CompressedAddress::new(next_byte(&mut random), random as u32)
                .with_chain_or_height((random >> 32) as u32)
                .with_hash_or_index(random.rotate_left(17) as u32);

            for address in [
                CompressedAddress::new(0, 0),
                CompressedAddress::new(u8::MAX, u32::MAX)
                    .with_chain_or_height(u32::MAX)
                    .with_hash_or_index(u32::MAX),
                random_address,
            ] {
                check::<1>(&mut optimized, &mut reference, address, &mut random);
                check::<2>(&mut optimized, &mut reference, address, &mut random);
                check::<6>(&mut optimized, &mut reference, address, &mut random);
                check::<68>(&mut optimized, &mut reference, address, &mut random);
            }
        }
    }

    #[test]
    fn optimized_and_reference_hashing_are_exhaustively_differential() {
        let mut input = kat_input();
        assert!(slh_dsa_sha2_128_24_verify(&input));
        assert!(verify_with_reference_sha256(&input));

        // SYSCOIN: cover every ABI byte, including every FORS, WOTS, and
        // Merkle signature component, with a deterministic one-bit mutation.
        for offset in 0..input.len() {
            input[offset] ^= 1;
            let reference = verify_with_reference_sha256(&input);
            let optimized = slh_dsa_sha2_128_24_verify(&input);
            assert_eq!(
                optimized, reference,
                "differential mismatch at byte {offset}"
            );
            assert!(!optimized, "mutated KAT accepted at byte {offset}");
            input[offset] ^= 1;
        }
    }

    #[test]
    fn verifier_never_panics_for_length_boundaries_or_arbitrary_inputs() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        for len in [0, 1, 31, 32, 63, 64, 95, 96, 3951, 3952, 3953, 8192] {
            let input = vec![0x5a; len];
            assert!(
                catch_unwind(AssertUnwindSafe(|| { slh_dsa_sha2_128_24_verify(&input) })).is_ok()
            );
        }

        let mut random = 0x6a09_e667_f3bc_c908u64;
        for _ in 0..16 {
            let mut input = vec![0u8; INPUT_LEN];
            for byte in &mut input {
                random ^= random >> 12;
                random ^= random << 25;
                random ^= random >> 27;
                *byte = random.wrapping_mul(0x2545_f491_4f6c_dd1d) as u8;
            }
            // Make the public-key words canonical so arbitrary signatures
            // exercise every checked fixed-offset parser path.
            input[N..32].fill(0);
            input[32 + N..64].fill(0);
            assert!(
                catch_unwind(AssertUnwindSafe(|| { slh_dsa_sha2_128_24_verify(&input) })).is_ok()
            );
        }
    }

    #[test]
    fn every_noncanonical_public_key_padding_byte_rejects() {
        let mut input = kat_input();
        for offset in (N..32).chain(32 + N..64) {
            input[offset] = 1;
            assert!(!slh_dsa_sha2_128_24_verify(&input), "padding byte {offset}");
            input[offset] = 0;
        }
    }

    #[test]
    fn fixed_resources_are_identical_and_charged_before_parsing() {
        fn spent(input: &[u8]) -> BaseResources<DecreasingNative> {
            let before = BaseResources::<DecreasingNative>::FORMAL_INFINITE;
            let mut after = before.clone();
            let mut output = Vec::new();
            SlhDsaSha212824VerifyImpl::execute(input, &mut output, &mut after, Global)
                .expect("sufficient resources");
            before.diff(after)
        }

        let valid = spent(&kat_input());
        let malformed = spent(&[0u8; 3]);
        let invalid = spent(&[0u8; INPUT_LEN]);
        assert_eq!(valid, malformed);
        assert_eq!(valid, invalid);
        assert_eq!(valid.ergs(), SLH_DSA_SHA2_128_24_VERIFY_COST_ERGS);
        assert_eq!(
            valid.native().as_u64(),
            SLH_DSA_SHA2_128_24_VERIFY_NATIVE_COST
        );

        let mut output = Vec::new();
        let mut insufficient_ergs = BaseResources::<DecreasingNative>::from_ergs_and_native(
            zk_ee::system::Ergs(SLH_DSA_SHA2_128_24_VERIFY_COST_ERGS.0 - 1),
            DecreasingNative::from_computational(SLH_DSA_SHA2_128_24_VERIFY_NATIVE_COST),
        );
        assert!(SlhDsaSha212824VerifyImpl::execute(
            &kat_input(),
            &mut output,
            &mut insufficient_ergs,
            Global,
        )
        .is_err());
        assert!(output.is_empty());

        let mut exact = BaseResources::<DecreasingNative>::from_ergs_and_native(
            SLH_DSA_SHA2_128_24_VERIFY_COST_ERGS,
            DecreasingNative::from_computational(SLH_DSA_SHA2_128_24_VERIFY_NATIVE_COST),
        );
        SlhDsaSha212824VerifyImpl::execute(&kat_input(), &mut output, &mut exact, Global)
            .expect("exact fixed resources must succeed");
        assert_eq!(output.len(), 32);
    }
}
