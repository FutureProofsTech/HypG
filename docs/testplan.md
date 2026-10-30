# Validation plan and evidence record

**Status:** v2.0.0 / DS 2.0.1 research prototype. This document records
what was tested, how, and what the results do and do not imply. A local
test pass is not an audit, a proof, or a certification.

## 1. Evidence levels

| Level | Name | Example | Weight |
|---:|---|---|---|
| E0 | Source inspection | Manual review of arithmetic and layouts | Necessary, not sufficient |
| E1 | Deterministic tests | Unit tests, KAT files, doc-tests | Strong within tested inputs |
| E2 | Adversarial harness | Bit-flip sweeps, malformed inputs, panic sweep | Broad but not exhaustive |
| E3 | Dynamic/portability analysis | Miri subsets, cross-architecture KATs, alternate targets | Partial assurance |
| E4 | Independent review | External audit, cryptanalysis, formal proof | **None** |

The release evidence is mostly E1–E3. There is no E4 evidence. The
project does not describe E1–E3 results as an audit.

## 2. Exact test inventory

On commit `c14169edd8c5cf520150c3b872f03f2237b244ac` (2026-10-30),
`cargo test --workspace --locked` reports **146 passed, 0 failed, 0
ignored**. The same total passes in release mode and on the MSRV 1.70
toolchain.

| Suite | Tests | Kind |
|---|---:|---|
| `hypg-core` | 38 | Unit |
| `hypg-kem` | 9 | Unit |
| `hypg-ds` | 23 | Unit |
| `hypg-hash` | 9 | Unit |
| `hypg-symm` | 13 | Unit |
| `hypg-aead` | 6 | Unit |
| `hypg-mt` | 2 | Unit |
| `hypg-lattice` | 3 | Unit |
| `hypg-kat` | 5 | Unit |
| `hypg-cli` negative integration | 25 | Integration |
| Doc-tests across eight crates | 13 | Documentation |
| **Total** | **146** | |

`hypg-bench`, `hypg-cli`, and `hypg-redteam` binaries contain no
`#[test]` functions. They are CI gates, not counted as tests.

The 13 doc-tests are distributed as: AEAD 2, core 1, DS 1, hash 3, KAT
3, KEM 1, mt 1, symm 1.

## 3. Commands and observed results

### 3.1 Debug suite

```bash
cargo test --workspace --locked
```

Observed on the record machine:

```text
146 passed; 0 failed; 0 ignored
```

### 3.2 Release suite

```bash
cargo test --workspace --locked --release
```

Observed:

```text
146 passed; 0 failed
```

Release mode uses `panic = "abort"`, fat LTO, one codegen unit, and
stripped binaries. This catches codegen-sensitive behaviour that a
debug-only run would miss.

### 3.3 MSRV suite

```bash
cargo +1.70 test --workspace --locked
```

Observed with `cargo 1.70.0`:

```text
146 passed; 0 failed
```

The workspace declares `rust-version = "1.70.0"`. The MSRV run is a
tested claim, not just a manifest field.

### 3.4 Formatting, lints, docs, audit

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit
```

These are required release gates. The workspace lints deny correctness,
suspicious, performance, pedantic, redundant-clone, and
redundant-field-name warnings. `cargo audit` has no external
dependencies to scan today, but the gate is present so that the first
external dependency cannot arrive unnoticed.

### 3.5 KAT gate

```bash
cargo test -p hypg-kat --lib --locked
```

This compares generated output byte-for-byte with the four frozen
files. The release gate also compares debug and release KAT output and
runs the complete KAT binary under a 1 MB stack.

## 4. Frozen KAT checksums

| File | Bytes | SHA-256 |
|---|---:|---|
| `crates/hypg-kat/kats/v2.0.0.txt` | 28,514 | `3b2dde3d1138c11b54a6880f50ca7b4390071ae53aa94601075f39b2af971d4b` |
| `crates/hypg-kat/kats-symm/v2.0.0.txt` | 3,662 | `91b7942ffb4a3c5da8b8b589268af7b7d1594796b428efdc7e26c567c5f04208` |
| `crates/hypg-kat/kats-hash/v2.0.0.txt` | 923 | `5fa778035ce2e8aa9c89345458ba4da67df4bdbe71a456cbb58026cf9341d9f1` |
| `crates/hypg-kat/kats-ds/v2.0.1.txt` | 201,015 | `e88c1bdf54e9390736cd03c1a165616d744a42c48d662880b344c7de3546c813` |

Total: **234,114 bytes**.

The DS `v2.0.0` KAT remains in the tree as historical evidence. It is
not the active gate. The active DS file is `v2.0.1.txt`.

### 4.1 Cross-architecture equality

```bash
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build -q -p hypg-kat --target aarch64-unknown-linux-musl
cargo run -q -p hypg-kat > /tmp/kat_x64.txt
qemu-aarch64 target/aarch64-unknown-linux-musl/debug/hypg-kat > /tmp/kat_arm64.txt
cmp /tmp/kat_x64.txt /tmp/kat_arm64.txt
```

Observed: identical **234,114 bytes** on x86-64 and `qemu-aarch64`. This
checks byte order, integer widths, and the DS 2.0.1 revision on a
big-endian-oriented instruction set emulation. It does not execute on a
native ARM64 machine and does not validate every target.

## 5. Adversarial harness (`hypg-redteam`)

The harness is deterministic and has 14 suites. On the record commit,
with default settings (`HYPG_REDTEAM_TRIALS=64`,
`HYPG_REDTEAM_FLIPS` default), the output was:

```text
PASS: S1 garbage-robustness
PASS: S2 malleability-sweep — 64 single-bit flips, 0 unchanged ss
PASS: S3 key-mismatch-matrix — 8x8, 0 off-diagonal anomalies
PASS: S4 message-extremes — 5 messages, 0 failures
PASS: S5 fo-binding — pk_bound=true coins_bound=true
PASS: S6 sampler-stats — n=524288, out_of_range=0
PASS: S7 failure-sweep — 64 trials, 0 failures
PASS: S8 determinism — stable=true sk_embeds_pk=true
PASS: S9 aead-adversarial — 0/64 tag flips held
PASS: S10 ds-forgery — 0/7 forgeries held
PASS: S11 adversarial-mega
PASS: S12 panic-sweep — KEM 300, AEAD 700, DS 11 adversarial cases
PASS: S13 sk-flip-sweep — 27 flips, 0 oracle failures
PASS: S14 streaming-aead — 24 games, 0 failures
redteam: all suites passed
```

### 5.1 Higher-cost runs

A fresh release run on the hardened commit used 20,000 trials:

```text
S7 failure-sweep — 20000 trials, 0 failures
all 14 suites passed
```

A separate fresh release run used `HYPG_REDTEAM_FLIPS=all`:

```text
S2 malleability-sweep — 11520 flips (all 11520 bit positions),
0 left ss unchanged
all 14 suites passed
```

The 20,000-trial run is a regression and sanity check, not a
`2^-128` failure bound. The full-bit sweep is exhaustive over bit
positions for one deterministic ciphertext, not over all ciphertexts.

### 5.2 What the harness does not do

- It is not coverage-guided fuzzing. There is no `cargo-fuzz`/AFL corpus,
  no coverage metric, and no mutation engine beyond deterministic flips.
- It does not test arbitrary key-generation seeds, arbitrary public keys,
  or protocol-level misuse.
- It does not measure timing, power, EM, or faults.
- It does not prove the absence of panics for every input; `S12` is a
  finite adversarial corpus.

## 6. Local lattice lab (`hypg-lattice`)

`cargo run -p hypg-lattice` performs five checks. Observed:

| Check | Result |
|---|---|
| L1 LLL 2D exactness vs brute force | 3 fixed bases, 0 mismatches |
| L2 toy LWE break (`n=8`, `m=16`, `q=257`) | planted 59, found 59, GH ≈ 42 |
| L3 dense 32-dim random lattice | shortest/GH ratio 1.09 |
| L4 real-parameter gap (`d=2049`, `log2 vol=12288`) | GH ≈ 699.6, target ≈ 45.3, gap 15.5×, LLL slack 2^1020 |
| L5 live KEM round-trip | `pk=1568`, `ct=1440` |

This lab validates the local LLL and primal-embedding harness on toy
instances and computes a coarse gap for the shipped dimensions. It is
not a BKZ cost estimate and does not replace the Sage lattice-estimator.
See [lattice-local.md](lattice-local.md) and [estimator.md](estimator.md).

## 7. Miri evidence

Miri is an interpreter for Rust's mid-level IR. It detects some
undefined behaviour, invalid pointer use, and data races on executed
paths. It does **not** prove absence of UB, and it is far slower than
native execution.

Latest recorded local runs on the hardened commit:

| Target | Tests | Time | Result |
|---|---:|---:|---|
| `hypg-kem` | 9/9 | 13,213.79 s | pass |
| `hypg-aead` | 6/6 | 214.46 s | pass |
| `hypg-ds` out-of-range/bounds tests | 3/3 | 0.42 s | pass |

The KEM run is the expensive one. The latest recorded subset does not
include full DS signing: building a 49,992-byte hypertree signature
under Miri is hours-long. The weekly `hypg-miri` workflow covers core,
symm, and KEM; AEAD is run locally when changed.

`hypg-ds` full-suite Miri coverage is **not claimed**. DS bounds tests
are not a substitute for full DS execution. `hypg-core` and `hypg-symm`
have had local Miri passes at earlier revisions; the latest recorded
subset in this documentation pass is the table above, and no broader
claim should be inferred.

## 8. CI matrix

The GitHub Actions workflow at `.github/workflows/ci.yml` runs:

- `cargo fmt --all -- --check`;
- clippy with workspace pedantic lints and `-D warnings`;
- debug test suite;
- library tests under `RUSTFLAGS="-C target-cpu=x86-64-v3"`;
- KAT snapshot and frozen-file gate;
- benchmark smoke with `HYPG_BENCH_ITERS=8`;
- red-team defaults;
- lattice lab;
- CLI round-trip smoke;
- cross-build for `aarch64-unknown-linux-gnu`;
- `wasm32-unknown-unknown` compile;
- `s390x-unknown-linux-gnu` check plus explicit little-endian grep gate;
- KAT and red-team under a 1 MB stack;
- cross-architecture KAT with static musl and `qemu-aarch64` when
  available;
- source gates for `unsafe`, panic macros, `unwrap`/`expect`, `Vec`,
  heap types, `String`, and `std` in the `no_std` libraries;
- zero-external-dependency assertion via `cargo tree`;
- rustdoc with `-D warnings`;
- `cargo audit`;
- MSRV 1.70 test suite;
- release test suite, release red-team, and debug/release KAT equality.

The local record in this document is not a claim that every CI job has
passed on GitHub. It records the commands and local results available
on this machine. The workflow is the reproducibility contract.

## 9. Benchmark evidence

The controlled release benchmark is recorded in
[metrics.md](metrics.md). It used:

```bash
HYPG_BENCH_ITERS=8 \
HYPG_BENCH_DS_ITERS=8 \
HYPG_BENCH_TTEST_N=10000 \
cargo run -q --release -p hypg-bench
```

The benchmark is a throughput and timing-smoke harness, not a
side-channel evaluation. The Welch t-test is informational and does not
gate the release. The machine is an Intel Core i5-14400F with 16
hardware threads, 31 GiB RAM, `rustc 1.97.1`, Linux x86-64.

## 10. Documentation-pass static gate

The documentation rewrite was accompanied by a local static gate on
2026-10-30:

| Check | Observed |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | clean |
| `cargo audit` | exit 0; 1,395 advisories loaded; no vulnerable dependency |
| `cargo tree --prefix none -e=no-dev` | workspace crates only |
| KAT and red-team under a 1 MB stack | pass |
| `aarch64-unknown-linux-gnu` build | pass |
| `wasm32-unknown-unknown` build | pass |
| `s390x-unknown-linux-gnu` check | pass |

The audit is vacuous in the sense that there are no external
dependencies; it is still a required gate. These checks do not replace
the full test matrix, the Miri subset, or external review.

## 11. Release checklist

A documentation/release commit is ready for local review only when all
of the following hold.

- [ ] Working tree clean before and after the commit.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace --locked` 146/146.
- [ ] `cargo test --workspace --locked --release` 146/146.
- [ ] `cargo +1.70 test --workspace --locked` 146/146.
- [ ] `cargo run -q -p hypg-redteam` all 14 suites pass.
- [ ] `cargo run -q -p hypg-lattice` all 5 checks pass.
- [ ] KAT SHA-256 values match §4.
- [ ] x86-64 and `qemu-aarch64` KAT output is byte-identical.
- [ ] `cargo run -q -p hypg-kat` under a 1 MB stack succeeds.
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` clean.
- [ ] `cargo audit` clean (or explicitly vacuous).
- [ ] No `unsafe`, external dependency, or `std` in the `no_std`
      libraries.
- [ ] Documentation links resolve; version map and KAT names agree.
- [ ] Commit is local only; no push unless the owner explicitly asks.

## 12. Evidence gaps

The following are **not** covered by the current evidence and must not be
claimed.

| Gap | Consequence |
|---|---|
| External audit / cryptanalysis | No independent assurance. |
| Sage lattice-estimator run | No Module-LWE bit-security estimate. |
| Formal constant-time / `dudect` | No timing-leakage claim. |
| Power/EM laboratory | No physical side-channel claim. |
| Fault-injection laboratory | No fault-resistance claim. |
| Formal verification | No machine-checked functional correctness. |
| Coverage-guided fuzzing | No coverage metric for parser/robustness. |
| Full DS Miri | No UB coverage for full signing. |
| Native ARM64 / s390x runtime | Cross-arch evidence is emulated or compile-only. |
| NIST ACVP/CAVP/CMVP | No standards validation. |
| Decapsulation failure bound | The 32-trial tripwire is not a `2^-128` proof. |
| Signing-volume analysis | No quantified FORS/hypertree bound. |

## 13. Audit handoff

For an external reviewer, the minimum evidence pack is:

1. This file and [metrics.md](metrics.md).
2. The frozen KAT files and their SHA-256 checksums.
3. `cargo test`, `cargo run -p hypg-redteam`, and
   `cargo run -p hypg-lattice` output on the exact commit.
4. The cross-architecture KAT comparison.
5. The Miri commands and outputs for the covered subsets.
6. `Cargo.lock`, toolchain version, target triple, and CPU model.
7. A written statement of the exact security claims, including the
   non-claims in [threat-model.md](threat-model.md).

The reviewer should be asked to attack the FO variant, the DS
composition and signing-volume bound, the `CA-PRF` role, the
constant-time claims, the AEAD composition, and the decapsulation
failure analysis. A passing test suite is not an answer to those
questions.
