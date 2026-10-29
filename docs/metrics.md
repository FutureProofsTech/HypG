# Local metrics (HypG v2.0.0 hardened profile, this PC)

Machine: Intel Core i5-14400F, 16 threads, 31 GiB RAM.
Toolchain: `rustc 1.97.1`, `cargo test` (debug) + `--release` harnesses.
Date of record: 2026-10-30. Reproduce with the commands below.

These are local measurements of a research prototype. They are not an
audit, a side-channel laboratory result, or a production-readiness
statement.

## Correctness (all local, all green)

| Gate | Result |
|---|---|
| `cargo test --workspace --locked` (debug AND release) | **129 pass**, 0 fail (96 unit: 32 core, 19 ds, 11 symm, 9 kem, 9 hash, 6 aead, 5 kat, 3 lattice, 2 mt; 20 CLI failure-path integration; 13 doc-tests) |
| `cargo +1.70 test --workspace --locked` (MSRV) | 129 pass, 0 fail |
| `hypg-redteam` (debug, defaults) | 14/14 suites PASS (incl. `S12` panic sweep, `S13` sk flips, `S14` streaming AEAD) |
| `hypg-redteam` (release, **20000 trials**) | 14/14 PASS, **0 failures**, 0 unchanged-`ss` |
| `hypg-redteam` (release, `HYPG_REDTEAM_FLIPS=all`) | 14/14 PASS, all **11520** ciphertext bit flips change `ss` |
| `hypg-lattice` | 5/5 checks PASS (toy break exact, GH ratio 1.09, gap 15.5×) |
| Welch t-test sweep (release) | see timing row below; smoke signal only |
| `hypg-cli` round-trips + 20 failure-path tests | exit 2 usage / 3 auth-failure / 0 implicit-reject, all asserted |
| `cargo audit` | clean — 12 workspace crates, zero external deps, 0 advisories |
| `kat frozen-files` | byte-exact match (`kats/v2.0.0.txt`, `kats-symm/v2.0.0.txt`, `kats-ds/v2.0.0.txt`, `kats-hash/v2.0.0.txt`; v0.4–v0.7 kept as history) |
| Cross-builds | aarch64-gnu, wasm32 (libs), s390x `cargo check` + explicit-LE gate; 1 MB-stack KAT + redteam PASS |
| Cross-arch v2.0 KAT | musl-static `hypg-kat` under `qemu-aarch64` is byte-identical to x86-64 (234114/234114 bytes) |

Miri v2.0: `core` 32/32 and `symm` 11/11 pass. KEM was last run on
v1.0 (9/9); the v2.0 arithmetic-geometry change is not new `unsafe`,
but a fresh KEM pass is still required before citing it for v2.0.

## Performance (parameters v2.0, BLAKE3 + ChaCha)

```bash
HYPG_BENCH_ITERS=8 cargo run --release -p hypg-bench
```

| Op | Release avg (2026-10-30) | v1.0 release (historical) |
|---|---|---|
| KEM `keygen` / `encaps` / `decaps` | **751 / 914 / 1107 µs** | ~199 / ~288 / ~385 µs |
| AEAD `seal` / `open` (1 KiB) | **~3 / ~3 µs** | ~3 / ~3 µs |
| DS `sign` / `verify` | **45.7 ms / 2.25 ms** | ~62 ms / ~1.8 ms |
| DS `mt_sign` (16 workers) | **12.6 ms (~3.6×, byte-identical)** | ~12 ms (~5.2×) |

The KEM is slower because the module rank doubled (`k=2 → k=4`). DS
signing is faster per signature despite the larger hypertree because
the tree height per layer fell (`h'=5 → h'=4`) and the parallel split
changed.

## Bulk throughput at 1 MiB (release, 2026-10-30)

`hypg-bench` `big_1mib` lines (fixed 3 reps, integer MB/s):

| Primitive (1 MiB) | Release MB/s |
|---|---|
| `b3_hash` (one-shot) | **818** |
| `b3` streaming (64 KiB updates) | **820** |
| `b3_xof` output | **807** |
| ChaCha20 keystream | **754** |
| AEAD `seal` / `open` | **397 / 405** |

Streaming matches one-shot — no packaging cliff at chunk/buffer
boundaries. AEAD ≈ hash + stream cost, as the EtM construction predicts
(one ChaCha pass + one keyed-hash pass).

## Optimization profile (v2.0, release, `HYPG_BENCH_PROFILE=1`)

| Piece | Measured (v2.0) |
|---|---|
| Hash unit (128 B input) | ~162 ns |
| One WOTS+ key (67 chains + L-tree) | ~138 µs |
| One XMSS layer (16 WOTS keys + tree) | ~2.36 ms |
| FORS sign / verify | ~5.39 ms / ~64 µs |
| `CA-PRF` 1536 B vs plain KDF | ~4 vs ~1 µs |

Run `HYPG_BENCH_PROFILE=1 HYPG_BENCH_ITERS=4 cargo run --release -p hypg-bench`
to regenerate the exact microsecond lines on the target machine.

## Timing smoke (release, 2026-10-30)

Valid vs. tampered/forged medians (per-mille; 1000 = identical):
KEM decaps 1002pm, AEAD open 581pm (forged exits at tag check —
expected split, public geometry), DS verify 998pm. The Welch sweep
(`n = 10000`, 5 tamper spots) recorded max `|t| ≈ 1.65`, below the
4.5 smoke bar. These ratios are smoke signals, not a `dudect`-grade
study; a laboratory side-channel campaign remains external backlog.

## Red-team highlights (release, maximal local settings)

- `S2`: all **11520** bit flips (`HYPG_REDTEAM_FLIPS=all`) change `ss`.
- `S3`: 8×8 key-mismatch matrix, 0 anomalies.
- `S6`: 524288 CBD coeffs, range enclosed, mean **exactly 0**.
- `S7`: **20000/20000** round-trips clean at max load; the failure
  argument itself is the analytic noise margin in `spec.md` §5.
- `S11`: 12 burst faults held at 0; `pk` tamper breaks exchange; 4-cell
  garbage matrix panic-free and never collides; **17/17** DS pad flips
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

- Lattice-estimator run (needs Sage), `dudect` study, power/EM/fault
  laboratory work, and a third-party audit: tracked in
  `docs/estimator.md` / `docs/audit-prep.md`.
- `cargo-fuzz`/`libFuzzer` would violate the zero-dependency policy;
  the deterministic `hypg-redteam` sweep is the local substitute.
