//! `hypg-core`: deterministic hyper-graph cellular automata primitive.
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`.
//!
//! Prototype, frozen at v1.0, unaudited — do not deploy. See
//! `docs/threat-model.md`.
//!
//! Forward-only automaton (fixed-size state, secret rule expansion,
//! branchless steps, boundary folding, `CA-PRF`), Module-LWE polynomial
//! layer (`R_q`, `q = 2^12`, rank 2), portable BLAKE3 (hash/XOF/keyed/
//! derive, oracle-validated), and `ChaCha20` stream cipher — plus
//! constant-time helpers. v0.7 replaced the original from-scratch
//! SHA3/Keccak with BLAKE3 (see `CHANGELOG.md`); no Keccak remains.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod b3;
pub mod caprf;
pub mod chacha;
pub mod ct;
pub mod fold;
pub mod params;
pub mod poly;
pub mod rule;
pub mod state;
pub mod step;

pub use params::{
    CT_LEN, FAKE_LEN, PK_LEN, ROUNDS, RULE_WORDS, SEED_LEN, SK_LEN, SS_LEN, STATE_BYTES,
    STATE_WORDS,
};
pub use rule::Rule;
pub use state::State;
