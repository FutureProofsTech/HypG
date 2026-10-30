//! Tweakable hash: every call binds `pubseed`, `ADRS`, and a registry domain.
//!
//! v0.7: keyed BLAKE3 with `pubseed` as the MAC key (the primitive's
//! designed use) instead of prefixed SHA3 — shorter inputs, same tweak
//! discipline. Domains live in `docs/domains.md`.
//!
//! v2.0.1 wire revision: `PRF` and `F` both take 64-byte payloads under
//! the same key, so each input now starts with an explicit one-byte
//! domain tag (`0x01` / `0x02`). This removes the structural collision
//! that existed when a secret seed happened to equal a public address.

use hypg_core::b3::b3_keyed;
use hypg_core::ct::zeroize;

use crate::addr::Addr;
use crate::params::N;

/// Domain tag for secret-value derivation (`PRF`).
const TAG_PRF: u8 = 0x01;
/// Domain tag for chain steps (`F`).
const TAG_F: u8 = 0x02;

/// `PRF(pubseed, seed, addr)`: secret-value derivation.
#[must_use]
pub fn prf(pubseed: &[u8; N], seed: &[u8; N], addr: &Addr) -> [u8; N] {
    let mut input = [0u8; 1 + 2 * N];
    input[0] = TAG_PRF;
    let mut i = 0usize;
    while i < N {
        input[1 + i] = seed[i];
        i += 1;
    }
    i = 0;
    while i < N {
        input[1 + N + i] = addr.0[i];
        i += 1;
    }
    let mut out = [0u8; N];
    b3_keyed(pubseed, &input, &mut out);
    zeroize(&mut input);
    out
}

/// Chain step `F(pubseed, addr, x)`.
#[must_use]
pub fn f(pubseed: &[u8; N], addr: &Addr, x: &[u8; N]) -> [u8; N] {
    let mut input = [0u8; 1 + 2 * N];
    input[0] = TAG_F;
    let mut i = 0usize;
    while i < N {
        input[1 + i] = addr.0[i];
        i += 1;
    }
    i = 0;
    while i < N {
        input[1 + N + i] = x[i];
        i += 1;
    }
    let mut out = [0u8; N];
    b3_keyed(pubseed, &input, &mut out);
    zeroize(&mut input);
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
    zeroize(&mut input);
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
    fn prf_and_f_are_domain_separated_even_on_identical_payload() {
        // Before the v2.0.1 tag revision, `seed == addr` and `x == addr`
        // made the two 64-byte inputs byte-identical. The explicit tags
        // must keep them apart.
        let ps = [0x11u8; N];
        let seed = [0x22u8; N];
        let a = Addr([0x22u8; N]);
        assert_ne!(prf(&ps, &seed, &a), f(&ps, &a, &seed));
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
