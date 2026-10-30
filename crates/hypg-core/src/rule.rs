//! Secret micro-code rule tensor + deterministic expansion.
//!
//! The 64-bit-only rule space from the original pitch is insecure
//! (`2^64` brute force). `HypG` v0.1 instead expands a 256-bit seed
//! into an 8-word (512-bit) rule via the internal XOF.

use crate::b3::b3_expand;
use crate::ct::{zeroize, zeroize_u64};
use crate::params::{RULE_WORDS, SEED_LEN};

/// Non-abelian local transition micro-code.
///
/// Expanded from a secret seed, so `Debug` is redacted and `Drop`
/// best-effort zeroizes the words.
#[derive(Clone)]
pub struct Rule(pub [u64; RULE_WORDS]);

impl core::fmt::Debug for Rule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rule { .. }")
    }
}

impl Drop for Rule {
    fn drop(&mut self) {
        zeroize_u64(&mut self.0);
    }
}

impl Rule {
    /// Expand `seed` under `domain` into rule words (little-endian).
    #[must_use]
    pub fn expand(seed: &[u8; SEED_LEN], domain: &[u8]) -> Self {
        let mut bytes = [0u8; RULE_WORDS * 8];
        b3_expand(&mut bytes, seed, domain);
        let mut words = [0u64; RULE_WORDS];
        let mut i = 0usize;
        while i < RULE_WORDS {
            let o = i * 8;
            words[i] = u64::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ]);
            i += 1;
        }
        zeroize(&mut bytes);
        Self(words)
    }
}
