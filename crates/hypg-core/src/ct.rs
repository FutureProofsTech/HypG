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
/// `bit` must be 0 or 1; `a`/`b` equal length (public).
pub fn ct_select(out: &mut [u8], a: &[u8], b: &[u8], bit: u8) {
    let mask = bit.wrapping_neg();
    let mut i = 0usize;
    while i < out.len() && i < a.len() && i < b.len() {
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
