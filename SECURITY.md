# SECURITY.md — HypG

## Status: hardened research profile v2.0, unconfirmed hardness, unaudited

HypG v2.0 is a **breaking parameter-hardening release**. It raises the
Module-LWE KEM to NIST Category-5 *dimensions* (`n = 256`, `k = 4`,
lattice dimension 1024, `q = 2^12`) and moves signatures to an
SLH-DSA-256f-shaped profile (`n = 32`, `h = 68`, `d = 17`, `h' = 4`,
FORS `35×9`). The BLAKE3 / ChaCha20 primitives and `HYP-G/v07/...`
domain strings are unchanged.

Matching NIST parameter dimensions is **not** a security certification.
Bit-security is estimated, not confirmed, and the signature composition
has not been independently reviewed. Do not use for real key exchange,
encryption, or signatures; do not cite KAT vectors as security evidence.

## Reporting

Research discussion only; no bounty. The API may change in future
versions. If you find a flaw in frozen invariants (non-determinism,
nonzero failure rate, panic on valid input, memory unsafety — the latter
should be impossible in safe Rust), open an issue with reproducer +
`cargo test` output + target triple.

## Roadmap to any security claim

1. Lattice-estimator confirmation + parameter review (`k = 4`,
   `q = 4096` vs Kyber-1024's `3329`).
2. Third-party cryptanalysis (KEM trapdoor, `CA-PRF` heuristic, EtM
   mode binding incl. the streaming front, DS `(h,d,k,a,w)` composition
   bounds).
3. Timing/fault evaluation harness (DS signing is hypertree-heavy and
   unmeasured for leakage — branchless by construction, untested).
4. Independent audit of automaton + polynomial + BLAKE3/ChaCha +
   KEM + AEAD + DS code.

Until all four land, every release keeps this warning.
