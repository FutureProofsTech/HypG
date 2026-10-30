//! `CA-PRF`: deterministic expander with the hyper-graph automaton in the middle.
//!
//! `out = KDF(CA(XOF(seed, domain || "-init")) || domain || "-out")`.
//!
//! The outer `KDF` (BLAKE3) keeps output uniform in the ROM even if the CA
//! is biased; the CA contributes 32 branchless rounds of non-linear,
//! non-abelian mixing as a heuristic hedge. All loops public and fixed.

use crate::b3::{b3_expand, b3_kdf};
use crate::ct::zeroize;
use crate::params::{SEED_LEN, STATE_BYTES};
use crate::rule::Rule;
use crate::state::State;
use crate::step::run;

/// Expand `seed` under `domain` into `out.len()` bytes via the CA.
///
/// `out.len()` is always a public constant at call sites.
pub fn ca_expand(out: &mut [u8], seed: &[u8; SEED_LEN], domain: &[u8]) {
    // Stage 1: `init = XOF(seed, domain || "-init")`.
    let mut init_tag = [0u8; 64];
    let mut tlen = 0usize;
    let mut i = 0usize;
    while i < domain.len() && tlen < init_tag.len() - 5 {
        init_tag[tlen] = domain[i];
        tlen += 1;
        i += 1;
    }
    let suffix = b"-init";
    let mut k = 0usize;
    while k < suffix.len() {
        init_tag[tlen] = suffix[k];
        tlen += 1;
        k += 1;
    }
    let mut init = [0u8; STATE_BYTES];
    b3_expand(&mut init, seed, &init_tag[..tlen]);

    // Stage 2: CA evolution (branchless, fixed rounds).
    let rule = Rule::expand(seed, domain);
    let mut st = State::from_bytes_le(&init);
    run(&mut st, &rule);
    let mut state_bytes = st.to_bytes_le();

    // Stage 3: `out = KDF(state || domain || "-out")`.
    let mut otag = [0u8; 64];
    let mut olen = 0usize;
    i = 0;
    while i < domain.len() && olen < otag.len() - 4 {
        otag[olen] = domain[i];
        olen += 1;
        i += 1;
    }
    let osuf = b"-out";
    k = 0;
    while k < osuf.len() {
        otag[olen] = osuf[k];
        olen += 1;
        k += 1;
    }
    b3_kdf(out, &[state_bytes.as_slice(), &otag[..olen]], domain);
    zeroize(&mut init);
    zeroize(&mut state_bytes);
    zeroize(&mut init_tag);
    zeroize(&mut otag);
}

/// Convenience: 32-byte CA-PRF output.
#[must_use]
pub fn ca32(seed: &[u8; SEED_LEN], domain: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    ca_expand(&mut out, seed, domain);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let seed = [0x77u8; 32];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        ca_expand(&mut a, &seed, b"test");
        ca_expand(&mut b, &seed, b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn domain_separated() {
        let seed = [0x77u8; 32];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        ca_expand(&mut a, &seed, b"dom-a");
        ca_expand(&mut b, &seed, b"dom-b");
        assert_ne!(a, b);
    }

    #[test]
    fn output_length_shapes() {
        // Empty, single-byte, and non-block-aligned shapes (callers use
        // 32..1536). The terminal XOF makes shorter outputs strict
        // prefixes of longer ones under the same `(seed, domain)`.
        let seed = [0x77u8; 32];
        let mut full = [0u8; 100];
        ca_expand(&mut full, &seed, b"shapes");
        for len in [0usize, 1, 33, 100] {
            let mut a = [0u8; 100];
            ca_expand(&mut a[..len], &seed, b"shapes");
            assert_eq!(&a[..len], &full[..len], "prefix mismatch at len {len}");
        }
    }
}
