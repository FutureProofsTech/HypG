# HypG v2.0 Normative Spec (Category-5 dimensions)

Status: **FROZEN for 2.0 (parameters v2.0). Module-LWE + FO KEM research
profile at NIST Category-5 dimensions, pending estimator confirmation +
audit. Not for deployment.**
Platinum: `no_std`, zero dependencies, bit-exact LE.
(`forbid(unsafe_code)` holds — the portable primitives are safe Rust.)

v2.0 raises the Module-LWE module rank from `k = 2` to `k = 4`
(lattice dimension 1024) and is a breaking wire-format change. The
`HYP-G/v07/...` domain strings and the BLAKE3 / ChaCha20 primitives are
unchanged; v1.0 vectors remain in the tree as historical evidence.

## 0. Terminology

- `SEED`: 32-byte master secret. Only secret input to `KeyGen`.
- `RULE`/`STATE`: 8-word micro-code / `[u64; 32]` CA state (256 B).
- `R_q = Z_q[X]/(X^256+1)`, `q = 2^12 = 4096`, module rank `k = 4`.
- `PK`: `seed_a(32) || pack12(b_vec)(1536)` = 1568 B.
- `CT`: `pack10(c1_vec)(1280) || pack5(c2)(160)` = 1440 B.
- `SS`: 32 B. `SK`: `seed(32) || fake(32) || pk(1568)` = 1632 B.

## 1. Sizes, ring, endianness

| Param | Value | Notes |
|---|---|---|
| `STATE_WORDS` / `ROUNDS` | 32 / 32 | CA unchanged |
| `POLY_N` / `MODULE_K` | 256 / 4 | `X^256+1`, dim 1024 |
| `MOD_Q` | 4096 (`2^12`) | mask `0xFFF`, shifts only |
| `C1` compress | `12→10` | `((c+2)>>2)&0x3FF`, 320 B/poly |
| `C2` compress | `12→5` | `((c+64)>>7)&0x1F`, 160 B |
| `PK_LEN` | 1568 = 32 + 1536 | `4·(256·12/8)` |
| `CT_LEN` | 1440 = 1280 + 160 | `4·(256·10/8) + 256·5/8` |
| `SK_LEN` | 1632 | seed + fake + pk |
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
r-seed, ss, reject`). Matrix `A` (16 polys, 6144 B) and all secrets
flow through `CA-PRF` (outer BLAKE3 preserves ROM uniformity).

## 3. CA core (unchanged algorithm)

Identical round schedule to v0.1/v0.2 (strides 1/5/17, `ROUNDS = 32`).
The CA is the deterministic randomness substrate; `fold_*` remain as
utilities, not `pk`/`ct` definers.

## 4. Module arithmetic (`hypg-core::poly`, branchless)

- `add/sub`: wrapping + `& 0xFFF`.
- `mul`: naive negacyclic `O(256²)` = 65,536 mults in `i64`
  (`max 256·4095² ≈ 4.3e9`, no overflow), mask-only mod.
- `dot`: `Σᵢ aᵢ·bᵢ` over public-length slices (rank 4 in the KEM).
- `encode(m)`: bit `i` → `coeff = bit << 11` (spacing 2048).
- `decode(v)`: `bit = (((v + 1024) mod 4096) >> 11) & 1`.
- `compress10/decompress`, `compress5/decompress` as above.
- `pack12` (384 B/poly), bit-stream `pack10` (320 B) / `pack5` (160 B).
- `CBD(eta=2)` from 128 B; `uniform` from 384 B.

## 5. PKE (Module-LWE)

- `KeyGen(seed)`: `seed_a = CA-PRF(seed)`; `A = uniform(seed_a)` (`4×4`);
  `s,e = CBD(...)` (length-4 vectors); `b = A·s + e`;
  `pk = seed_a || pack12(b)`; `fake = CA-PRF(seed)`;
  `sk = seed || fake || pk`.
- `Encrypt(pk, m)`: `r_seed = BLAKE3(m || pk || r-seed)`;
  `r,e1 = CBD` vectors, `e2 = CBD` poly; `A = uniform(seed_a)`;
  `c1 = A^T·r + e1`; `c2 = b^T·r + e2 + encode(m)`;
  compress + pack.
- `Decrypt(s, ct)`: `v = c2 − s^T·c1` → `decode`.

Noise per coeff ≈ `e^T·r + e₂ − s^T·e₁` + compression terms:
`e^T·r` and `s^T·e₁` each have std `~32` at rank 4 (combined `~45`),
`c1`-compression adds `~9`, `c2`-compression `~37`, so total std is
`~60` vs threshold `1024` (>16σ — cryptographically negligible). The
32-trial CI sample expects 0 failures; the red-team failure sweep runs
20,000 trials at release.

## 6. KEM (FO, implicit rejection)

Identical FO shape to v0.2 with new sizes:
`ss = KDF(m || ct || pk_hash)` on success,
`KDF(fake || ct)` on re-encryption mismatch (`ct_eq` full-scan +
`ct_select`). Deterministic in `(pk, coins)`; caller supplies randomness.

## 7. Security position (honest)

- Structurally a Module-LWE + FO KEM at NIST Category-5 *dimensions*
  (`n = 256`, `k = 4`, dim 1024, `q = 4096`, `eta = 2`) with
  power-of-two `q` chosen for branchless mask-only reduction (no Barrett
  division; deviation from Kyber's `3329` is intentional and documented).
- Expected hardness is in the Kyber-1024 neighborhood, but **not
  confirmed**: the larger `q` changes the lattice profile, and the
  lattice-estimator run is still pending. Parameter review and a
  third-party audit are also pending — hence still a research profile,
  **do not deploy**.
- Matching NIST dimensions is not the same as matching NIST's security
  analysis, implementation history, or assurance level. No such claim
  is made.
- Side channels: same branchless posture, no power/EM/fault claims.

## 8. Tests / gates (Phase 4)

- `cargo test`: core (BLAKE3 oracle vectors, `pack12/10/5`, `encode`, `mul` incl.
  `X^255·X = −1`, noise-margin + sampler-range, `ct_eq/select/zeroize`,
  `CA-PRF`), 9 KEM (sweep, tamper/wrong-key, determinism, 32-trial
  zero-failure), 5 KAT (round-trip + byte-exact frozen-file match).
- `cargo run -p hypg-kat`: must byte-match the frozen v2.0.0 file; any
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
- Local records in `docs/metrics.md` (release: 751/914/1107 µs
  keygen/encaps/decaps; 20,000-trial + full-11,520-flip redteam clean;
  Welch timing ratios recorded as per-mille smoke tests); operator rules
  in `docs/deployment.md`; history in `CHANGELOG.md`.
- `clippy -D warnings` (pedantic), `fmt --check`, ARM64 cross-build,
  `cargo doc -D warnings`, `unsafe`/`Vec`/`std` grep-gates on libs.
- Estimator + audit backlog tracked in `docs/estimator.md` and
  `docs/audit-prep.md` (not gated in CI; no Sage in-tree).
