//! Boundary-state folding ("chaos entropic anchor").
//!
//! The 256-byte state is folded over itself into compact public outputs.
//! Folding is branchless and public-index only.
//!
//! These helpers are *utilities*, not `pk`/`ct` definers: the KEM's wire
//! formats are the Module-LWE packings in `hypg-kem`. Consequently every
//! helper here is total for any `State` and returns a fixed-size buffer.

use crate::params::{CT_LEN, STATE_BYTES, STATE_WORDS};
use crate::state::State;

/// Ciphertext core length (`CT_LEN` minus the 32-byte tag).
pub const CT_CORE_LEN: usize = CT_LEN - 32;

/// Fold full state into a 256-byte public blob:
/// `out[i] = S[i] ^ ROTL(S[(i+16) mod 32],23) ^ S[31-i] ^ dom(i)`
/// (word-wise, LE output).
#[must_use]
pub fn fold_pk(state: &State) -> [u8; STATE_BYTES] {
    let mut words = [0u64; STATE_WORDS];
    let mut i = 0usize;
    while i < STATE_WORDS {
        let a = state.0[i];
        let b = state.0[(i + STATE_WORDS / 2) % STATE_WORDS].rotate_left(23);
        let c = state.0[STATE_WORDS - 1 - i];
        words[i] = a ^ b ^ c ^ 0xA5A5_A5A5_A5A5_A5A5u64.wrapping_add(i as u64);
        i += 1;
    }
    let mut out = [0u8; STATE_BYTES];
    let mut i = 0usize;
    while i < STATE_WORDS {
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

/// Fold full state into a 256-byte ciphertext-core blob:
/// `out[i] = S[i] ^ ROTL(S[(i+16) mod 32],31) ^ S[(7i+3) mod 32] ^ dom(i)`
/// (word-wise, LE output).
#[must_use]
pub fn fold_ct_core(state: &State) -> [u8; STATE_BYTES] {
    let mut words = [0u64; STATE_WORDS];
    let mut i = 0usize;
    while i < STATE_WORDS {
        let a = state.0[i];
        let b = state.0[(i + STATE_WORDS / 2) % STATE_WORDS].rotate_left(31);
        let c = state.0[(i * 7 + 3) % STATE_WORDS];
        words[i] = a ^ b ^ c ^ 0x5A5A_5A5A_5A5A_5A5Au64.wrapping_add((i as u64).wrapping_mul(3));
        i += 1;
    }
    let mut out = [0u8; STATE_BYTES];
    let mut i = 0usize;
    while i < STATE_WORDS {
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

/// Assemble `CT_LEN`-byte ciphertext from a `CT_CORE_LEN`-byte core and
/// a 32-byte tag. Total for every input.
#[must_use]
pub fn assemble_ct(core: &[u8; CT_CORE_LEN], tag: &[u8; 32]) -> [u8; CT_LEN] {
    let mut ct = [0u8; CT_LEN];
    let mut i = 0usize;
    while i < CT_CORE_LEN {
        ct[i] = core[i];
        i += 1;
    }
    let mut j = 0usize;
    while j < 32 {
        ct[CT_CORE_LEN + j] = tag[j];
        j += 1;
    }
    ct
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        let mut bytes = [0u8; STATE_BYTES];
        let mut i = 0usize;
        while i < STATE_BYTES {
            bytes[i] = u8::try_from(i).unwrap_or(0).wrapping_mul(0x1D).wrapping_add(3);
            i += 1;
        }
        State::from_bytes_le(&bytes)
    }

    #[test]
    fn folds_are_total_and_domain_separated() {
        let s = state();
        let pk = fold_pk(&s);
        let ct = fold_ct_core(&s);
        assert_eq!(pk.len(), STATE_BYTES);
        assert_eq!(ct.len(), STATE_BYTES);
        assert_ne!(pk, ct);
        assert_eq!(pk, fold_pk(&s));
    }

    #[test]
    fn every_state_word_reaches_the_fold() {
        // A fold that silently skipped words would still be total; this
        // pins that each word contributes to the output.
        let base = state();
        let want = fold_pk(&base);
        let mut w = 0usize;
        while w < STATE_WORDS {
            let mut altered = base.clone();
            altered.0[w] ^= 1;
            assert_ne!(fold_pk(&altered), want, "state word {w} ignored");
            w += 1;
        }
    }

    #[test]
    fn assemble_ct_layout() {
        let mut core = [0u8; CT_CORE_LEN];
        let mut i = 0usize;
        while i < CT_CORE_LEN {
            core[i] = u8::try_from(i & 0xFF).unwrap_or(0).wrapping_add(1);
            i += 1;
        }
        let tag = [0xA5u8; 32];
        let ct = assemble_ct(&core, &tag);
        assert_eq!(&ct[..CT_CORE_LEN], &core[..]);
        assert_eq!(&ct[CT_CORE_LEN..], &tag[..]);
    }
}
