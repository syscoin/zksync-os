const SYSCOIN_SHA256_ROUND_CSR: u32 = 0x7cb;

/// SYSCOIN: invoke one Airbender SHA-256 round transition. Schedule expansion
/// remains ordinary guest code in the caller.
///
/// ABI:
/// - x10: 4-byte-aligned R/W pointer to the eight-word working state
/// - x11: 4-byte-aligned read pointer to expanded schedule word `W[t]`
/// - x12: numeric SHA-256 round constant `K[t]`
#[inline(always)]
pub(super) fn sha256_round(working_state: &mut [u32; 8], word: &u32, round_constant: u32) {
    let state_address = core::ptr::from_mut(working_state).addr();
    let word_address = core::ptr::from_ref(word).addr();
    debug_assert_eq!(state_address % core::mem::align_of::<u32>(), 0);
    debug_assert_eq!(word_address % core::mem::align_of::<u32>(), 0);
    let state_end = state_address + core::mem::size_of_val(working_state);
    let word_end = word_address + core::mem::size_of_val(word);
    debug_assert!(state_end <= word_address || word_end <= state_address);

    unsafe {
        core::arch::asm!(
            "csrrw x0, {csr}, x0",
            csr = const SYSCOIN_SHA256_ROUND_CSR,
            in("x10") state_address,
            in("x11") word_address,
            in("x12") round_constant,
            options(nostack)
        );
    }
}
