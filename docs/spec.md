# HypG v0.7 Normative Spec (BLAKE3 + ChaCha migration; lattice unchanged)

Status: **FROZEN for 1.0 (parameters v0.7, unchanged). Module-LWE + FO
KEM prototype, Kyber-class parameters, pending estimator confirmation
+ audit. Not for deployment.**
Platinum: `no_std`, zero dependencies, bit-exact LE.
(`forbid(unsafe_code)` holds — the new portable primitives are safe Rust.)

v0.7 replaces SHA3/Keccak with portable BLAKE3 + ChaCha20 throughout
(see `CHANGELOG.md`); lattice parameters, APIs, and sizes are unchanged.

## 0. Terminology

- `SEED`: 32-byte master secret. Only secret input to `KeyGen`.
- `RULE`/`STATE`: 8-word micro-code / `[u64; 32]` CA state (256 B).
- `R_q = Z_q[X]/(X^256+1)`, `q = 2^12 = 4096`, module rank `k = 2`.
- `PK`: `seed_a(32) || pack12(b_vec)(768)` = 800 B.
- `CT`: `pack10(c1_vec)(640) || pack5(c2)(160)` = 800 B.
- `SS`: 32 B. `SK`: `seed(32) || fake(32) || pk(800)` = 864 B.

## 1. Sizes, ring, endianness

| Param | Value | Notes |
|---|---|---|
| `STATE_WORDS` / `ROUNDS` | 32 / 32 | CA unchanged |
| `POLY_N` / `MODULE_K` | 256 / 2 | `X^256+1`, dim 512 |
| `MOD_Q` | 4096 (`2^12`) | mask `0xFFF`, shifts only |
| `C1` compress | `12→10` | `((c+2)>>2)&0x3FF`, 320 B/poly |
| `C2` compress | `12→5` | `((c+64)>>7)&0x1F`, 160 B |
| `PK_LEN` | 800 = 32 + 768 | `2·(256·12/8)` |
| `CT_LEN` | 800 = 640 + 160 | `2·(256·10/8) + 256·5/8` |
| `SK_LEN` | 864 | seed + fake + pk |
| `MSG` | 32 B, 1 bit/coeff | spacing `q/2 = 2048` |
| `CBD eta` | 2 | `-2..=2`, 128 B/poly |
| Endianness | LE | all conversions |

## 2. Hash / XOF / KDF / CA-PRF (from-scratch, zero-dep)

v0.7 replaces SHA3/Keccak with portable BLAKE3 (`hypg-core::b3`:
hash, streaming XOF, keyed hash, `derive_key`; scalar, no SIMD —
the official crate's job). Streaming `Hasher` (chunk tree + fixed
54-deep CV stack) needs no allocation. Every mode is pinned against
official-crate oracle vectors (see `b3.rs` tests; provenance recorded).

`CA-PRF(seed, domain) = KDF(CA(XOF(seed))…)` keeps its 3-stage shape;
inner XOF/KDF are BLAKE3 now. v0.7 domains use the `HYP-G/v07/...`
prefix (same names as v03, bumped to mark the primitive change;
`seed-a, sec-s, sec-e, poly-a, rand-r, rand-e1, rand-e2, fake,
r-seed, ss, reject`). Matrix `A` (4 polys, 1536 B) and all secrets
flow through `CA-PRF` (outer BLAKE3 preserves ROM uniformity).

## 3. CA core (unchanged algorithm)

Identical round schedule to v0.1/v0.2 (strides 1/5/17, `ROUNDS = 32`).
The CA is the deterministic randomness substrate; `fold_*` remain as
utilities, not `pk`/`ct` definers.

## 4. Module arithmetic (`hypg-core::poly`, branchless)

- `add/sub`: wrapping + `& 0xFFF`.
- `mul`: naive negacyclic `O(256²)` = 65,536 mults in `i64`
  (`max 256·4095² ≈ 4.3e9`, no overflow), mask-only mod.
- `dot2`: `a₀·b₀ + a₁·b₁` for `2`-vectors.
- `encode(m)`: bit `i` → `coeff = bit << 11` (spacing 2048).
- `decode(v)`: `bit = (((v + 1024) mod 4096) >> 11) & 1`.
- `compress10/decompress`, `compress5/decompress` as above.
- `pack12` (384 B/poly), bit-stream `pack10` (320 B) / `pack5` (160 B).
- `CBD(eta=2)` from 128 B; `uniform` from 384 B.

## 5. PKE (Module-LWE)

- `KeyGen(seed)`: `seed_a = CA-PRF(seed)`; `A = uniform(seed_a)` (`2×2`);
  `s,e = CBD(...)` (length-2 vectors); `b = A·s + e`;
  `pk = seed_a || pack12(b)`; `fake = CA-PRF(seed)`;
  `sk = seed || fake || pk`.
- `Encrypt(pk, m)`: `r_seed = BLAKE3(m || pk || r-seed)`;
  `r,e1 = CBD` vectors, `e2 = CBD` poly; `A = uniform(seed_a)`;
  `c1 = A^T·r + e1`; `c2 = b^T·r + e2 + encode(m)`;
  compress + pack.
- `Decrypt(s, ct)`: `v = c2 − s^T·c1` → `decode`.

Noise per coeff ≈ `e^T·r + e₂ − s^T·e₁` + compression terms:
LWE part std `~32`, `c1`-error term `~9`, `c2`-error `~37` → total
std `~50` vs threshold `1024` (`Q(20)` — cryptographically negligible).
32-trial CI sample expects 0 failures (heavier ops than v0.2, hence
fewer trials to keep debug CI fast).

## 6. KEM (FO, implicit rejection)

Identical FO shape to v0.2 with new sizes:
`ss = KDF(m || ct || pk_hash)` on success,
`KDF(fake || ct)` on re-encryption mismatch (`ct_eq` full-scan +
`ct_select`). Deterministic in `(pk, coins)`; caller supplies randomness.

## 7. Security position (honest)

- Structurally a Module-LWE + FO KEM at Kyber-512-class dimensions
  (`n = 256`, `k = 2`, dim 512, `q = 4096`, `eta = 2`) with power-of-two
  `q` chosen for branchless mask-only reduction (no Barrett division;
  deviation from Kyber's `3329` is intentional and documented).
- Expected hardness is in the Kyber-512 neighborhood (~100+ bit
  classical; quantum sieve models lower). **Pending**: lattice-estimator
  run, parameter review, third-party audit — hence still `0.x`,
  **do not deploy**.
- v0.2's size-constrained toy (`n = 64`, `<256 B`) is superseded; the
  `<256 B` target is formally retired as incompatible with 128-bit PQ
  at current knowledge (all NIST finalists exceed it).
- Side channels: same branchless posture, no power/EM/fault claims.

## 8. Tests / gates (Phase 4)

- `cargo test`: core (BLAKE3 oracle vectors, `pack12/10/5`, `encode`, `mul` incl.
  `X^255·X = −1`, noise-margin + sampler-range, `ct_eq/select/zeroize`,
  `CA-PRF`), 6 KEM (sweep, tamper/wrong-key, determinism, 32-trial
  zero-failure), 2 KAT (round-trip + byte-exact frozen-file match).
- `cargo run -p hypg-kat`: must byte-match the frozen file; any
  intentional vector change requires a spec version bump + new file.
- `HYPG_BENCH_ITERS=8 cargo run -p hypg-bench`: throughput averages +
  valid/tampered `decaps` timing ratio smoke (per-mille, informational).
- `cargo run -p hypg-redteam` (`HYPG_REDTEAM_TRIALS`, `HYPG_REDTEAM_FLIPS`):
  garbage robustness, malleability sweep, mismatch matrix, extremes,
  FO binding, sampler stats, failure sweep, determinism.
- `hypg-cli keygen/encaps/decaps` round-trip (OS-random + fixed-vector).
- `SecretKey::zeroize` / `SharedSecret::zeroize` coverage.
- `cargo run -p hypg-lattice`: LLL exactness, toy-LWE break, dense GH
  check, real-parameter gap, live round-trip (see `docs/lattice-local.md`).
- Local records in `docs/metrics.md` (release: ~274–496/346–661/427–528 µs
  keygen/encaps/decaps across runs; 100000-trial + full-800-flip redteam
  clean; Welch max |t| ≈ 2.0 at n = 2000 across 5 tamper spots, t = −0.34
  at n = 5000); operator rules in `docs/deployment.md`; history in
  `CHANGELOG.md`.
- `clippy -D warnings` (pedantic), `fmt --check`, ARM64 cross-build,
  `cargo doc -D warnings`, `unsafe`/`Vec`/`std` grep-gates on libs.
- Estimator + audit backlog tracked in `docs/estimator.md` and
  `docs/audit-prep.md` (not gated in CI; no Sage in-tree).
