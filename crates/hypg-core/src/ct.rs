//! Constant-time helpers (branchless w.r.t. secrets).
//!
//! No secret branches, no secret indices, no early returns.

/// Constant-time equality for equal-length slices.
/// Returns `1` if equal, `0` otherwise. Loops over all bytes.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    // Lengths are public protocol constants; a mismatch is a hard 0.
    // (Length check itself is on public values, not secrets.)
    if a.len() != b.len() {
        return 0;
    }
    let mut diff: u8 = 0;
    let mut i = 0usize;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    // Branchless normalize without `if` on secrets:
    // diff == 0 -> (0-1)>>8 = 0xFFFF>>8 = 0xFF -> &1 = 1 (equal)
    // diff != 0 -> (d-1)>>8 == 0 -> &1 = 0
    let d = u16::from(diff);
    ((d.wrapping_sub(1) >> 8) & 1) as u8
}

/// Constant-time select: `out = pick(secret_bit, a, b)`.
/// `bit` is normalized to its low bit; `a`/`b` must have `out.len()`
/// bytes (public). On a length mismatch the output is zeroized instead
/// of being partially written.
pub fn ct_select(out: &mut [u8], a: &[u8], b: &[u8], bit: u8) {
    if out.len() != a.len() || a.len() != b.len() {
        zeroize(out);
        return;
    }
    let mask = (bit & 1).wrapping_neg();
    let mut i = 0usize;
    while i < out.len() {
        out[i] = (a[i] & mask) | (b[i] & !mask);
        i += 1;
    }
}

/// Best-effort stack zeroization in 100% safe Rust.
/// Uses normal writes + compiler fence + `black_box` so the stores
/// are observable and not elided. (True volatile erasure would need
/// `unsafe`; platinum policy keeps `forbid(unsafe_code)`.)
pub fn zeroize(buf: &mut [u8]) {
    let mut i = 0usize;
    while i < buf.len() {
        buf[i] = 0;
        i += 1;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(buf.as_mut_ptr());
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Best-effort erasure for `u16` word buffers (polynomial coefficients).
pub fn zeroize_u16(buf: &mut [u16]) {
    let mut i = 0usize;
    while i < buf.len() {
        buf[i] = 0;
        i += 1;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(buf.as_mut_ptr());
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Best-effort erasure for `u32` word buffers (BLAKE3 state words).
pub fn zeroize_u32(buf: &mut [u32]) {
    let mut i = 0usize;
    while i < buf.len() {
        buf[i] = 0;
        i += 1;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(buf.as_mut_ptr());
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Best-effort erasure for `u64` word buffers (automaton state/rule).
pub fn zeroize_u64(buf: &mut [u64]) {
    let mut i = 0usize;
    while i < buf.len() {
        buf[i] = 0;
        i += 1;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(buf.as_mut_ptr());
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Best-effort erasure for fixed-size arrays of byte arrays (e.g. WOTS
/// secret chains, FORS/XMSS levels). Total for any geometry.
pub fn zeroize_nested<const M: usize, const L: usize>(buf: &mut [[u8; M]; L]) {
    let mut i = 0usize;
    while i < L {
        zeroize(&mut buf[i]);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_vectors() {
        assert_eq!(ct_eq(&[], &[]), 1);
        assert_eq!(ct_eq(&[0u8; 32], &[0u8; 32]), 1);
        assert_eq!(ct_eq(&[1u8; 32], &[1u8; 32]), 1);
        assert_eq!(ct_eq(&[0u8; 32], &[1u8; 32]), 0);
        // Single-bit difference at each edge position must report 0.
        let mut a = [0xAAu8; 32];
        let b = [0xAAu8; 32];
        assert_eq!(ct_eq(&a, &b), 1);
        a[0] ^= 0x01;
        assert_eq!(ct_eq(&a, &b), 0);
        a[0] ^= 0x01;
        a[31] ^= 0x80;
        assert_eq!(ct_eq(&a, &b), 0);
        // Public length mismatch is a hard 0 (lengths are protocol constants).
        assert_eq!(ct_eq(&[0u8; 32], &[0u8; 31]), 0);
    }

    #[test]
    fn select_vectors() {
        let a = [0xF0u8; 16];
        let b = [0x0Fu8; 16];
        let mut out = [0u8; 16];
        ct_select(&mut out, &a, &b, 1);
        assert_eq!(out, a);
        ct_select(&mut out, &a, &b, 0);
        assert_eq!(out, b);
        // Non-binary bit uses its low bit; mismatched lengths fail closed.
        ct_select(&mut out, &a, &b, 3);
        assert_eq!(out, a);
        let mut short = [0xAAu8; 8];
        ct_select(&mut short, &a, &b, 1);
        assert_eq!(short, [0u8; 8]);
    }

    #[test]
    fn zeroize_clears() {
        let mut buf = [0xA5u8; 64];
        zeroize(&mut buf);
        assert_eq!(buf, [0u8; 64]);
        let mut empty: [u8; 0] = [];
        zeroize(&mut empty);
    }
}
