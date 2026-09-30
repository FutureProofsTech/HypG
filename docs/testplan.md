# Test plan (HypG)

What runs automatically, what stays manual, and the per-release
consistency checklist. Local-only scope: lab items (Sage estimator,
power/EM, human audit) live in `docs/estimator.md` / `docs/audit-prep.md`.

## 1. Automated matrix (CI + `cargo test`)

| Suite | What | Where | CI step |
|---|---|---|---|
| Unit (core) | BLAKE3 oracles, ChaCha vectors + counter-exhaustion, poly pack/CBD/mul/commutativity, `ct` ops, `caprf` shapes | `hypg-core/src/**/tests` | `tests`, `tests under x86-64-v3`, release `tests` |
| Unit (KEM) | round-trips, tamper/key rejection, determinism, encaps determinism, `sizes_ok` | `hypg-kem/src/lib.rs` | same as above |
| Unit (AEAD) | sweep, tamper, `fits_block_space` edges, nonce-reuse doc, 256×1-byte exhaustive, `sizes_ok` | `hypg-symm/src/lib.rs` | same as above |
| Unit (hash) | empty/`abc` oracles, XOF-64 prefix, streaming equivalence, keyed/derive separation, shapes, `sizes_ok` | `hypg-hash/src/lib.rs` | same as above |
| Unit (DS) | addr/tweak/WOTS-checksum/`split`, XMSS 0/31, FORS 0/127, hypertree, round-trip, forgery, `sizes_ok` | `hypg-ds/src/**` | same as above |
| Unit (mt) | serial equivalence, worker-count stability | `hypg-mt/src/lib.rs` | same as above (incl. v3) |
| Integration (CLI) | 20 failure paths (exit 2 usage / 3 auth / 0 implicit-reject) | `hypg-cli/tests/` | `tests` (debug + release) |
| Doc-tests (7) | `b3_hash`, KEM round-trip, seal/open + forgery, `ds_sign`, `mt_sign`, KAT renderers | doc comments | `tests` (debug + release) |
| KAT frozen | byte-exact vs `kats*/v0.7.0.txt` (KEM, symm, DS, **hash**), cross-arch x86-64/AArch64, debug/release identical | `hypg-kat` | `kat snapshot`, `kat frozen-file gate`, cross-arch, release `kat snapshot` |
| Redteam S1–S14 | garbage, malleability (head+tail, `all` = 6400 bits), mismatch, extremes, FO binding, sampler, failure sweep, determinism, AEAD, DS forgery, mega-suite, panic sweep, sk flips, streaming AEAD | `hypg-redteam` | `red-team harness`, release red-team, 1 MB-stack run |
| Unit (AEAD stream) | chunk-split equivalence, tamper/truncate/swap/duplicate rejection, poison, empty, determinism | `hypg-aead/src/lib.rs` | same as above |
| Lattice L1–L5 | LLL exactness, toy break, GH ratio, gap, live round-trip | `hypg-lattice` | `lattice lab` |
| Bench | throughput, valid/forged median pairs (KEM/AEAD/DS), Welch sweep (`HYPG_BENCH_TTEST_N`), DS profiler | `hypg-bench` | `bench + timing smoke` |
| Portability | aarch64 compile + qemu KAT diff, wasm32 compile, s390x `cargo check`, explicit-LE grep gate | CI | cross-build steps, LE gate |
| Hygiene | fmt, clippy pedantic, unsafe/`panic!`/`unwrap`/`Vec`/heap-type/std gates, zero-dep assertion, `cargo audit`, docs | CI | gate steps |
| MSRV | full 107-test suite on toolchain 1.70 | CI | `msrv` job |
| Miri (weekly) | symm + kem libs UB-clean (DS excluded, rationale §3) | CI | `nightly-miri` workflow |

## 2. Per-release checklist (manual, ~15 min)

- [ ] Size tables match code: KEM `pk = ct = 800`, `sk = 864`, `ss = 32`;
      AEAD `key = 32`, `nonce = 12`, `tag = 32`; DS `pk = 64`,
      `sk = 128`, `sig = 35456` (`docs/spec*.md` vs `sizes_ok` tests).
- [ ] Domain registry (`docs/domains.md`) matches every `HYP-G/v07/*`
      literal in code (`grep -rhn "HYP-G/" crates/*/src | sort -u`).
- [ ] Public API signatures match spec §API
      (`keygen/encaps/decaps`, `seal/open`, `ds_sign/ds_verify`,
      `mt_sign`, KAT renderers).
- [ ] KAT files frozen and listed: `kats/v0.7.0.txt`,
      `kats-symm/v0.7.0.txt`, `kats-ds/v0.7.0.txt`,
      `kats-hash/v0.7.0.txt`.
- [ ] `docs/metrics.md` numbers re-recorded (bench release,
      t-test max `|t|`, redteam max-load counts, Miri/audit/MSRV status).
- [ ] KAT coverage audit: every pillar must keep ≥2 distinct
      seeds/messages (currently KEM 3 coins, symm 5 cases, DS 2×2,
      hash 3 inputs + keyed/derive) —
      else extend the renderer + re-freeze (spec version bump).
- [ ] `CHANGELOG.md` entries for behavior changes (exit codes, new
      suites, new gates).
- [ ] Max-load commands re-run (see §3) and counts updated.

## 3. Manual procedures (exact commands)

Max load (release, this PC):

```sh
HYPG_REDTEAM_TRIALS=20000 HYPG_REDTEAM_FLIPS=800 cargo run -q --release -p hypg-redteam
HYPG_REDTEAM_FLIPS=all cargo run -q --release -p hypg-redteam   # 6400-bit S2
HYPG_BENCH_TTEST_N=10000 HYPG_BENCH_ITERS=8 cargo run -q --release -p hypg-bench
```

Miri (core only; KEM/DS too slow — documented, not attempted):

```sh
cargo +nightly miri test -p hypg-core --lib   # minutes
cargo +nightly miri test -p hypg-symm --lib   # minutes
cargo +nightly miri test -p hypg-kem --lib    # ~75 min locally; weekly CI
# DS excluded: hypertree signing under Miri is hours-long; DS shares the
# Miri-clean primitives and is covered by S10/S11/S12 redteam sweeps.
```

wasm runtime (needs a runner; compile gate is in CI):

```sh
# with node or wasmtime installed, drive a cdylib probe per docs;
# without a runner only the wasm32 compile gate applies.
```

s390x runtime (needs an s390x sysroot — Fedora ships no
`glibc-s390x-linux-gnu`; compile + LE gates are in CI):

```sh
CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=s390x-linux-gnu-gcc \
  cargo build -p hypg-kat --target s390x-unknown-linux-gnu  # needs sysroot glibc
qemu-s390x target/s390x-unknown-linux-gnu/debug/hypg-kat | diff - <(cargo run -q -p hypg-kat)
```

## 4. Standing arguments (not re-tested per run)

- Endianness: zero `ne_bytes`/`transmute` in libs (CI grep gate);
  every conversion is explicit-LE; s390x `cargo check` proves BE compile.
- `panic = "abort"` release profile: release `cargo test` covers it.
- Timing: median pairs + Welch sweep are smoke signals only; lab-grade
  side-channel campaigns stay external by policy.
