# Local metrics (HypG v1.0.0 frozen prototype, parameters v0.7/v0.6, this PC)

Machine: Intel Core i5-14400F, 16 threads, 31 GiB RAM.
Toolchain: `rustc 1.97.1`, `cargo test` (debug) + `--release` harnesses.
Date of record: 2026-09-29. Reproduce with the commands below.

## Correctness (all local, all green)

| Gate | Result |
|---|---|
| `cargo test --workspace --locked` (debug AND release) | **129 pass**, 0 fail (96 unit: 32 core, 19 ds, 11 symm, 9 kem, 9 hash, 6 aead, 5 kat, 3 lattice, 2 mt; 20 CLI failure-path integration; 13 doc-tests) |
| `cargo +1.70 test --workspace --locked` (MSRV) | 129 pass, 0 fail (one fix required: inline-`const` → underscore-`const` in `poly.rs`; MSRV now verified, CI-gated) |
| `hypg-redteam` (debug, defaults) | 14/14 suites PASS (incl. `S12` panic sweep, `S13` sk flips, `S14` streaming AEAD) |
| `hypg-redteam` (release, **20000 trials** / 816 flips) | 14/14 PASS, **0 failures**, 0 unchanged-`ss` |
| `hypg-redteam` (release, `HYPG_REDTEAM_FLIPS=all`) | 14/14 PASS, all **6400** bit flips change `ss` |
| `hypg-lattice` | 5/5 checks PASS (toy break exact, GH ratio 1.09, gap 15.4×) |
| Welch t-test sweep (release, `n = 10000`, 5 tamper spots) | max **|t| ≈ 1.23** (2026-09-29 freeze re-run; earlier 0.58) — no signal, bar is 4.5 |
| Cross-arch runtime KAT (musl static + `qemu-aarch64`) | KEM + Symm + DS output **byte-identical** x86-64 vs AArch64 |
| `hypg-cli` round-trips + 20 failure-path tests | exit 2 usage / 3 auth-failure / 0 implicit-reject, all asserted |
| `cargo +nightly miri test` | core 29/29, symm 11/11, kem 9/9 PASS (kem ≈ 74 min — weekly CI, not per-push; DS excluded: hours-long, documented in `testplan.md`) |
| `cargo audit` | clean — 10 workspace crates, zero external deps, 0 advisories |
| `kat frozen-files` | byte-exact match (`kats/v0.7.0.txt`, `kats-symm/v0.7.0.txt`, `kats-ds/v0.7.0.txt`, `kats-hash/v0.7.0.txt`; v0.4–v0.6 kept as history) |
| KAT message coverage audit (Phase 4) | second-message vectors already present in all pillars (KEM 3 coins, symm 5 cases, DS 2 seeds × 2 msgs) — no frozen-file churn needed |
| Cross-builds | aarch64-gnu, wasm32 (libs), s390x `cargo check` + explicit-LE gate; 1 MB-stack KAT + redteam PASS |

## Performance (parameters v0.7, BLAKE3 + ChaCha — frozen for 1.0)

```bash
HYPG_BENCH_ITERS=200 HYPG_BENCH_DS_ITERS=3 cargo run --release -p hypg-bench
```

| Op | Debug avg | Release avg (freeze 2026-09-29) | v0.6.0 release (Keccak) |
|---|---|---|---|
| KEM `keygen` / `encaps` / `decaps` | ~4200 / ~4600 / ~1800 µs | **~199 / ~288 / ~385 µs** | ~274 / ~375 / ~465 µs |
| AEAD `seal` / `open` (1 KiB) | ~75 µs | **~3 / ~3 µs** | ~4 µs |
| DS `sign` / `verify` | ~1100 ms / ~34 ms | **~62 ms / ~1.8 ms** | ~148 ms / ~4.4 ms |
| DS `mt_sign` (16 workers) | — | **~12 ms (~5.2×, byte-identical)** | — |

Migration speedup measured: **1.3× KEM, 2.5× DS sign, 2.4× DS verify**
(matches the pre-migration spike prediction of ~2× portable).

## Bulk throughput at 1 MiB (release, 2026-09-29)

`hypg-bench` `big_1mib` lines (fixed 3 reps, integer MB/s; debug in
parentheses — unoptimized, for scale only):

| Primitive (1 MiB) | Release MB/s | Debug MB/s |
|---|---|---|
| `b3_hash` (one-shot) | **836** | 41 |
| `b3` streaming (64 KiB updates) | **841** | 41 |
| `b3_xof` output | **808** | 45 |
| ChaCha20 keystream | **752** | 42 |
| AEAD `seal` / `open` | **395 / 395** | 20 / 20 |

Bar was >100 MB/s per primitive: **held everywhere** (hash ≈ 800,
stream ≈ 700, AEAD ≈ 370). Streaming matches one-shot — no packaging
cliff at chunk/buffer boundaries. AEAD ≈ hash + stream cost, as the
EtM construction predicts (one ChaCha pass + one keyed-hash pass).

## Optimization profile (v0.7.0 breakdown, release, `HYPG_BENCH_PROFILE=1`)

Cost model confirmed by measurement (`xmss_pk_layer ≈ 32 × wots_key`,
`ds_sign ≈ 12 × xmss_pk_layer + fors_sign`):

| Piece | Measured (v0.7.0) | v0.6.0 (Keccak) |
|---|---|---|
| Hash unit (128 B input) | ~160 ns (BLAKE3 1 block) | ~250–300 ns/perm |
| One WOTS+ key (67 chains + L-tree) | ~140 µs | ~320–370 µs |
| One XMSS layer (32 WOTS keys + tree) | ~4.6 ms | ~11–12 ms |
| FORS sign / verify | ~1.2 ms / ~0.04 ms | ~3.3–3.7 ms / ~0.13 ms |
| `CA-PRF` 1536 B vs plain KDF | ~6 vs ~2 µs | ~50 vs ~29 µs |

## Optimization profile (v0.7.0: BLAKE3 migration + retired Keccak work)

Measured migration speedup (release): **1.3× KEM, 2.5× DS sign
(148 ms → 60 ms), 2.4× DS verify** — matching the pre-migration spike
prediction of ~2× portable. The v0.6 Keccak micro-opts (~5–10%) and the
PGO negative result below are retained as history.

PGO: **measured harmful, do not use.** Two training volumes × two
`llvm-profdata` builds (system 22.1.8 and toolchain-matched 22.1.6)
all reproduce a ~2.6× slowdown (`ds_sign` ≈ 143 ms → ≈ 390 ms),
uniform across ops — consistent with LLVM layout/inlining heuristics
fighting branchless idioms under fat LTO, not with bad training data.
Repro: `RUSTFLAGS="-Cprofile-generate=DIR" cargo build --release`,
train with bench+redteam+kat, `llvm-profdata merge`,
`RUSTFLAGS="-Cprofile-use=DIR/pgo.profdata" cargo build --release`.

Conclusion update: the 50 ms DS-sign target is now in range
(60 ms measured) without touching parameters or invariants. Remaining
options if it must go lower: portable-BLAKE3 micro-opts (~1.2×),
`128f`-style parameter timing (bench decides), or a parameter change
(new analysis + KATs).

SIMD: investigated and documented in `docs/simd.md` — no intrinsics
under `forbid(unsafe)`, portable SIMD nightly-only, batch-4
auto-vectorization attempt reverted after measuring zero gain;
ISA matrix (x86_64/v3, aarch64+qemu, thumbv7em, wasm32) green.

Timing smoke (valid vs. tampered/forged medians, 2026-09-29 release):
KEM 1008pm, AEAD 559pm (forged exits at tag check — expected split,
public geometry), DS verify **1001pm**;
Welch tests above show no split visible to this harness (not a proof;
`dudect`-grade study remains backlog).

## Red-team highlights (release, maximal local settings)

- `S2`: all **6400** bit flips (`HYPG_REDTEAM_FLIPS=all`) change `ss`.
- `S3`: 8×8 key-mismatch matrix, 0 anomalies.
- `S6`: 524288 CBD coeffs, range enclosed, mean **exactly 0** (per-mille 0).
- `S7`: **20000/20000** round-trips clean at max load (plus 100000/100000
  on the identical lattice code pre-migration — empirical supplement; the
  failure argument itself is the analytic `±1024` vs `~50` std margin in
  `spec.md` §5).
- `S11`: 12 burst faults held at 0; `pk` tamper breaks exchange; 4-cell
  garbage matrix panic-free and never collides; 12/12 DS pad flips
  reject; 2-message multi-sign verifies without cross-verification;
  1 MiB AEAD round-trips with head/tail tamper rejected.
- `S12`: 1011-case corpus (300 KEM + 700 AEAD + 11 DS), 0 panics,
  0 violations.
- `S13`: 27 `sk` single-bit flips — seed/`pk` corruption breaks the
  exchange; fake-key corruption invisible on honest path, diverges
  reject output (spare-key design confirmed wired in).
- `S14`: 24 streaming games — 20 adversarial chunkings equal one-shot,
  reorder/truncate/duplicate fail with zeroed output, 1 MiB stream
  equals one-shot.
- `S9`: all 64 single-bit tag flips reject; ct/key/nonce/ad flips reject;
  empty-both round-trips; deterministic.
- `S10`: 0/7 signature forgeries held; message/key flips reject;
  deterministic.

## Dependencies / hygiene

- `cargo tree`: workspace crates only — **zero external dependencies**.
- `clippy --all-targets -D warnings`: clean (pedantic).
- `RUSTDOCFLAGS="-D warnings" cargo doc`: clean.

## Environment limits (not achievable on this PC)

- Lattice-estimator run (needs Sage), `dudect` study, third-party audit:
  tracked in `docs/estimator.md` / `docs/audit-prep.md`.
- `cargo-fuzz`/`libFuzzer` would violate the zero-dependency policy;
  the deterministic `hypg-redteam` sweep is the local substitute.
