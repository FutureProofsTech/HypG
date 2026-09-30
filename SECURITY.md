# SECURITY.md — HypG

## Status: frozen research prototype v1.0, unconfirmed hardness, unaudited

HypG v1.0 freezes the full suite (Module-LWE KEM + BLAKE3 hashing +
ChaCha20/keyed-BLAKE3 AEAD incl. streaming + hash-based signatures)
with parameters unchanged since v0.7 (KEM/AEAD/hash) and v0.6 (DS).
Signature composition bounds are cited, not confirmed; KEM/AEAD/hash
positions unchanged.

Bit-security is **estimated, not confirmed** everywhere. Do not use for
real key exchange, encryption, or signatures; do not cite KAT vectors
as security evidence.

## Reporting

Research discussion only; no bounty. The API is frozen at 1.0 (no
stability promise for future versions). If you find a flaw in frozen
invariants (non-determinism, nonzero failure rate, panic on valid
input, memory unsafety — the latter should be impossible in safe Rust),
open an issue with reproducer + `cargo test` output + target triple.

## Roadmap to any security claim

1. Lattice-estimator confirmation + parameter review (`q = 4096` vs `3329`).
2. Third-party cryptanalysis (KEM trapdoor, `CA-PRF` heuristic, EtM
   mode binding incl. the streaming front, DS composition bounds).
3. Timing/fault evaluation harness (DS signing is hypertree-heavy and
   unmeasured for leakage — branchless by construction, untested).
4. Independent audit of automaton + polynomial + BLAKE3/ChaCha +
   KEM + AEAD + DS code.

Until all four land, every release keeps this warning.
