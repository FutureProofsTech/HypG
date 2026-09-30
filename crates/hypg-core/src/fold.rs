//! Boundary-state folding ("chaos entropic anchor").
//!
//! The 256-byte state is folded over itself into compact public outputs.
//! Folding is branchless and public-index only.

use crate::params::{CT_LEN, PK_LEN, STATE_BYTES, STATE_WORDS};
use crate::state::State;

/// Fold full state into a 128-byte public key blob:
/// `pk[i] = S[i] ^ ROTL(S[i+16],23) ^ S[31-i]` (word-wise, LE output).
#[must_use]
pub fn fold_pk(state: &State) -> [u8; PK_LEN] {
    let mut words = [0u64; PK_LEN / 8];
    let mut i = 0usize;
    while i < words.len() {
        let a = state.0[i];
        let b = state.0[i + STATE_WORDS / 2].rotate_left(23);
        let c = state.0[STATE_WORDS - 1 - i];
        words[i] = a ^ b ^ c ^ 0xA5A5_A5A5_A5A5_A5A5u64.wrapping_add(i as u64);
        i += 1;
    }
    let mut out = [0u8; PK_LEN];
    let mut i = 0usize;
    while i < words.len() {
        let le = words[i].to_le_bytes();
        let mut k = 0usize;
        while k < 8 {
            out[i * 8 + k] = le[k];
            k += 1;
        }
        i += 1;
    }
    out
}

/// Fold full state into a 160-byte ciphertext core:
/// first 128 B like `fold_pk` with a different domain constant,
/// last 32 B = `b3(state_bytes)[..]` mixed with folded words.
/// (Hash part is added by the caller in `hypg-kem`; this helper
/// returns the 128-byte nonlinear part so KEM stays the orchestrator.)
#[must_use]
pub fn fold_ct_core(state: &State) -> [u8; PK_LEN] {
    let mut words = [0u64; PK_LEN / 8];
    let mut i = 0usize;
    while i < words.len() {
        let a = state.0[i];
        let b = state.0[i + STATE_WORDS / 2].rotate_left(31);
        let c = state.0[(i * 7 + 3) % STATE_WORDS];
        words[i] = a ^ b ^ c ^ 0x5A5A_5A5A_5A5A_5A5Au64.wrapping_add((i as u64).wrapping_mul(3));
        i += 1;
    }
    let mut out = [0u8; PK_LEN];
    let mut i = 0usize;
    while i < words.len() {
        let le = words[i].to_le_bytes();
        let mut k = 0usize;
        while k < 8 {
            out[i * 8 + k] = le[k];
            k += 1;
        }
        i += 1;
    }
    out
}

/// Full-state commitment helper: export state bytes for hashing.
/// Length is public (`STATE_BYTES`).
#[must_use]
pub fn state_bytes(state: &State) -> [u8; STATE_BYTES] {
    state.to_bytes_le()
}

/// Assemble `CT_LEN`-byte ciphertext from 128-byte core + 32-byte tag.
#[must_use]
pub fn assemble_ct(core: &[u8; PK_LEN], tag: &[u8; 32]) -> [u8; CT_LEN] {
    let mut ct = [0u8; CT_LEN];
    let mut i = 0usize;
    while i < PK_LEN {
        ct[i] = core[i];
        i += 1;
    }
    let mut j = 0usize;
    while j < 32 {
        ct[PK_LEN + j] = tag[j];
        j += 1;
    }
    ct
}
