//! Tweakable hash: every call binds `pubseed`, `ADRS`, and a registry domain.
//!
//! v0.7: keyed BLAKE3 with `pubseed` as the MAC key (the primitive's
//! designed use) instead of prefixed SHA3 — shorter inputs, same tweak
//! discipline. Domains live in `docs/domains.md`.

use hypg_core::b3::b3_keyed;

use crate::addr::Addr;
use crate::params::N;

/// `PRF(pubseed, seed, addr)`: secret-value derivation.
#[must_use]
pub fn prf(pubseed: &[u8; N], seed: &[u8; N], addr: &Addr) -> [u8; N] {
    let mut input = [0u8; 64];
    let mut i = 0usize;
    while i < N {
        input[i] = seed[i];
        i += 1;
    }
    i = 0;
    while i < N {
        input[N + i] = addr.0[i];
        i += 1;
    }
    let mut out = [0u8; N];
    b3_keyed(pubseed, &input, &mut out);
    out
}

/// Chain step `F(pubseed, addr, x)`.
#[must_use]
pub fn f(pubseed: &[u8; N], addr: &Addr, x: &[u8; N]) -> [u8; N] {
    let mut input = [0u8; 64];
    let mut i = 0usize;
    while i < N {
        input[i] = addr.0[i];
        i += 1;
    }
    i = 0;
    while i < N {
        input[N + i] = x[i];
        i += 1;
    }
    let mut out = [0u8; N];
    b3_keyed(pubseed, &input, &mut out);
    out
}

/// Tree node `H(pubseed, addr, left, right)`.
#[must_use]
pub fn h(pubseed: &[u8; N], addr: &Addr, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    let mut input = [0u8; 96];
    let mut i = 0usize;
    while i < N {
        input[i] = addr.0[i];
        i += 1;
    }
    i = 0;
    while i < N {
        input[N + i] = left[i];
        i += 1;
    }
    i = 0;
    while i < N {
        input[2 * N + i] = right[i];
        i += 1;
    }
    let mut out = [0u8; N];
    b3_keyed(pubseed, &input, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{T_TREE, T_WOTS_HASH};

    #[test]
    fn tweak_separation() {
        let ps = [0x11u8; N];
        let seed = [0x22u8; N];
        let mut a = Addr::zero();
        a.set_type(T_WOTS_HASH);
        let mut b = Addr::zero();
        b.set_type(T_TREE);
        assert_ne!(prf(&ps, &seed, &a), prf(&ps, &seed, &b));
        assert_ne!(f(&ps, &a, &seed), f(&ps, &b, &seed));
    }

    #[test]
    fn determinism() {
        let ps = [0x11u8; N];
        let x = [0x33u8; N];
        let a = Addr::zero();
        assert_eq!(f(&ps, &a, &x), f(&ps, &a, &x));
        assert_eq!(h(&ps, &a, &x, &x), h(&ps, &a, &x, &x));
    }
}
