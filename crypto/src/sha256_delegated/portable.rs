#[inline(always)]
fn big_sigma0(value: u32) -> u32 {
    value.rotate_right(2) ^ value.rotate_right(13) ^ value.rotate_right(22)
}

#[inline(always)]
fn big_sigma1(value: u32) -> u32 {
    value.rotate_right(6) ^ value.rotate_right(11) ^ value.rotate_right(25)
}

/// SYSCOIN: portable reference for the exact round transition implemented by
/// Airbender CSR 0x7cb. Schedule expansion is deliberately guest-side.
#[inline]
pub(super) fn sha256_round(working_state: &mut [u32; 8], word: &u32, round_constant: u32) {
    let [a, b, c, d, e, f, g, h] = *working_state;
    let choice = (e & f) ^ ((!e) & g);
    let majority = (a & b) ^ (a & c) ^ (b & c);
    let temp1 = h
        .wrapping_add(big_sigma1(e))
        .wrapping_add(choice)
        .wrapping_add(round_constant)
        .wrapping_add(*word);
    let temp2 = big_sigma0(a).wrapping_add(majority);
    *working_state = [
        temp1.wrapping_add(temp2),
        a,
        b,
        c,
        d.wrapping_add(temp1),
        e,
        f,
        g,
    ];
}
