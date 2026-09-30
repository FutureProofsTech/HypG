//! Branchless hyper-graph cellular automaton step.
//!
//! Invariants:
//! - No `if`/`else`, no `match` on secrets, no early returns.
//! - All loop bounds are public constants (`STATE_WORDS`, `ROUNDS`).
//! - No secret-dependent indices: neighborhood offsets are constants.
//! - Only `XOR/AND/OR/NOT/rotate/wrapping_add` on `u64`.
//!
//! The mixing is intentionally order-dependent (non-abelian): the
//! sequence `choice -> add -> rotate -> mul-xor` does not commute,
//! and hyper-edges use strides 1/5/17 to break locality.

use crate::params::{ROUNDS, RULE_WORDS, STATE_WORDS};
use crate::rule::Rule;
use crate::state::State;

/// Round constant base (golden-ratio derived, public).
const RC_BASE: u64 = 0x9E37_79B9_7F4A_7C15;
/// Round constant stride (pi-derived, public).
const RC_STRIDE: u64 = 0xBF58_476D_1CE4_E5B9;
/// Diffusion multiplier (odd, public).
const DIFF_MUL: u64 = 0xD6E8_FEB8_6659_FD93;

/// One full automaton evolution: `ROUNDS` branchless steps in place.
pub fn run(state: &mut State, rule: &Rule) {
    let mut round = 0usize;
    while round < ROUNDS {
        step_once(state, rule, round as u64);
        round += 1;
    }
}

/// Single round. `round` is public.
#[allow(clippy::many_single_char_names)]
fn step_once(s: &mut State, rule: &Rule, round: u64) {
    let rc = RC_BASE.wrapping_add((round.wrapping_add(1)).wrapping_mul(RC_STRIDE));
    let mut tmp = [0u64; STATE_WORDS];

    let mut i = 0usize;
    while i < STATE_WORDS {
        // Fixed public neighborhood (hyper-graph strides).
        let a = s.0[i];
        let b = s.0[(i + 1) % STATE_WORDS];
        let c = s.0[(i + 5) % STATE_WORDS];
        let d = s.0[(i + 17) % STATE_WORDS];
        let rk = rule.0[i % RULE_WORDS] ^ rc ^ ((i as u64).wrapping_mul(RC_STRIDE));

        // Non-linear choice (branchless mux): t = (t1 & d) ^ (~t1 & b).
        let t1 = a ^ b.rotate_left(13) ^ c.rotate_left(7);
        let t2 = (t1 & d) ^ ((!t1) & b);
        // Key injection + rotation + multiplicative diffusion.
        let t3 = t2.wrapping_add(rk ^ ((i as u64).wrapping_add(round)));
        let t4 = t3 ^ t3.rotate_left(29);
        let t5 = t4.wrapping_mul(DIFF_MUL) ^ d.rotate_left(11);
        // Cross-half bit-slice shuffle folded in (no extra pass).
        let partner = s.0[(i + STATE_WORDS / 2) % STATE_WORDS];
        tmp[i] = t5 ^ partner.rotate_left(17) ^ rc;
        i += 1;
    }

    // Commit (fixed copy, no conditionals).
    let mut j = 0usize;
    while j < STATE_WORDS {
        s.0[j] = tmp[j];
        j += 1;
    }
}

/// Initialize state deterministically from seed material (public mapping).
#[must_use]
pub fn init_from_bytes(seed_bytes: &[u8; 256]) -> State {
    State::from_bytes_le(seed_bytes)
}
