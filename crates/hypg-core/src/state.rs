//! Flat, pointerless automaton state: `[u64; 32]`.
//!
//! Little-endian byte order is normative across x86-64 and ARM64.

use crate::ct::zeroize_u64;
use crate::params::{STATE_BYTES, STATE_WORDS};

/// Dense hyper-graph state. Lives in registers / stack only.
///
/// Carries expanded key material, so `Debug` is redacted and `Drop`
/// best-effort zeroizes the words.
#[derive(Clone)]
pub struct State(pub [u64; STATE_WORDS]);

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("State { .. }")
    }
}

impl Drop for State {
    fn drop(&mut self) {
        zeroize_u64(&mut self.0);
    }
}

impl State {
    /// Zero state (useful for tests; never a valid key state).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u64; STATE_WORDS])
    }

    /// Initialize state from 256 bytes of key material (little-endian).
    #[must_use]
    pub const fn from_bytes_le(bytes: &[u8; STATE_BYTES]) -> Self {
        let mut words = [0u64; STATE_WORDS];
        let mut i = 0usize;
        while i < STATE_WORDS {
            let o = i * 8;
            words[i] = (bytes[o] as u64)
                | ((bytes[o + 1] as u64) << 8)
                | ((bytes[o + 2] as u64) << 16)
                | ((bytes[o + 3] as u64) << 24)
                | ((bytes[o + 4] as u64) << 32)
                | ((bytes[o + 5] as u64) << 40)
                | ((bytes[o + 6] as u64) << 48)
                | ((bytes[o + 7] as u64) << 56);
            i += 1;
        }
        Self(words)
    }

    /// Serialize state as little-endian bytes (normative).
    #[must_use]
    pub const fn to_bytes_le(&self) -> [u8; STATE_BYTES] {
        let mut out = [0u8; STATE_BYTES];
        let mut i = 0usize;
        while i < STATE_WORDS {
            let w = self.0[i];
            let o = i * 8;
            out[o] = (w & 0xff) as u8;
            out[o + 1] = ((w >> 8) & 0xff) as u8;
            out[o + 2] = ((w >> 16) & 0xff) as u8;
            out[o + 3] = ((w >> 24) & 0xff) as u8;
            out[o + 4] = ((w >> 32) & 0xff) as u8;
            out[o + 5] = ((w >> 40) & 0xff) as u8;
            out[o + 6] = ((w >> 48) & 0xff) as u8;
            out[o + 7] = ((w >> 56) & 0xff) as u8;
            i += 1;
        }
        out
    }
}

impl Default for State {
    fn default() -> Self {
        Self::zero()
    }
}
