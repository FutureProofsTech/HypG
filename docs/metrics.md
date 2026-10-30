# Measured performance and validation metrics

**Status:** local measurements of a research prototype. Not an audit,
not a side-channel laboratory result, and not a production benchmark.
The numbers describe this machine and this commit; they are not a
portable performance guarantee.

## 1. Record environment

| Item | Value |
|---|---|
| CPU | Intel Core i5-14400F, 10 cores / 16 threads |
| RAM | 31 GiB |
| OS | Linux x86-64 |
| Toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Profile | `--release` (`opt-level=3`, fat LTO, `codegen-units=1`, `panic=abort`, strip) |
| Record commit | `c14169edd8c5cf520150c3b872f03f2237b244ac` |
| Date of record | 2026-10-30 |

The controlled run was:

```bash
HYPG_BENCH_ITERS=8 \
HYPG_BENCH_DS_ITERS=8 \
HYPG_BENCH_TTEST_N=10000 \
cargo run -q --release -p hypg-bench
```

The benchmark performs a warmup round-trip before timing. KEM and AEAD
throughput values are integer averages over 8 iterations; DS values are
integer averages over 8 signing iterations. Large-message values use
three repetitions of a 1 MiB operation. Integer division truncates
microsecond averages, so small values have coarse resolution.

## 2. KEM

Sizes: `pk = 1568`, `ct = 1440`, `sk = 1632`, `ss = 32` bytes.

| Operation | Average |
|---|---:|
| Key generation | **795 µs** |
| Encapsulation | **931 µs** |
| Decapsulation | **1124 µs** |

Interleaved valid/tampered decapsulation medians:

| Input | Median |
|---|---:|
| Valid ciphertext | 1,107,761 ns |
| Tampered ciphertext | 1,113,174 ns |
| Tampered / valid | **1004 per-mille** |

A ratio of 1000 per-mille means identical medians. The observed 1004
is a 0.4% difference in this small sample. It is a smoke signal, not a
constant-time proof.

The cost is dominated by schoolbook negacyclic polynomial
multiplication. Decapsulation performs a full re-encryption and both
shared-secret derivations on every input.

## 3. AEAD

### 3.1 1 KiB messages

| Operation | Average |
|---|---:|
| Seal | **3 µs** |
| Open | **3 µs** |

Open medians:

| Input | Median |
|---|---:|
| Valid tag | 3,388 ns |
| Forged tag | 2,042 ns |
| Forged / valid | **602 per-mille** |

The forged path is faster because it computes the tag and rejects before
decryption; the valid path also decrypts. This is an expected
data-independent **public** length difference, not a secret-dependent
early return. It is not a complete timing analysis: the tag comparison
itself scans all 32 bytes, but the subsequent work differs by design.

### 3.2 1 MiB messages

| Operation | Throughput | µs/op |
|---|---:|---:|
| BLAKE3 hash | **842 MB/s** | 1245 |
| BLAKE3 streaming | **837 MB/s** | 1252 |
| BLAKE3 XOF | **827 MB/s** | 1268 |
| ChaCha20 XOR | **773 MB/s** | 1355 |
| AEAD seal | **427 MB/s** | 2455 |
| AEAD open | **434 MB/s** | 2412 |

The AEAD rate is lower than the raw stream/hash rates because it performs
both operations and the MAC pass. The streaming hash uses 64 KiB
updates, which checks that chunk-boundary handling does not impose a
packaging cliff.

## 4. Signatures

### 4.1 Serial sign/verify

| Operation | Average |
|---|---:|
| `ds_sign` | **72,009 µs** (72.0 ms) |
| `ds_verify` | **3,725 µs** (3.7 ms) |

DS verify medians:

| Input | Median |
|---|---:|
| Valid signature | 3,697,178 ns |
| Forged signature | 3,678,498 ns |
| Forged / valid | **994 per-mille** |

The forged signature flips a byte in `R`; verification still recomputes
the digest and most of the FORS/hypertree path before the root check,
so the medians are close. This is not a proof of constant-time
verification, and other forgery positions may exit earlier.

### 4.2 Threaded signing

| Operation | Average | Workers | Speedup |
|---|---:|---:|---:|
| `mt_sign` | **18,329 µs** (18.3 ms) | 16 | **3.928×** |

The threaded signer produces byte-identical signatures to `ds_sign`; the
benchmark asserts verification, and the DS KATs cover the serial path.
The speedup is sublinear because the 17 XMSS tree builds and 35 FORS
tree builds have different costs, the serial assembly remains, and the
small FORS units do not balance perfectly against the heavy XMSS units.
A 16-worker count is the platform parallelism on this machine, not a
portable recommendation.

## 5. Micro-profile

The optional profile run used `HYPG_BENCH_PROFILE=1` and
`HYPG_BENCH_ITERS=4`:

| Component | Measurement |
|---|---:|
| BLAKE3 over 128 B | ≈187 ns/hash |
| `CA-PRF` 1536 B | ≈4 µs |
| BLAKE3 KDF 1536 B | ≈1 µs |
| WOTS+ key (gen + chains + L-tree) | ≈223 µs |
| XMSS layer public key | ≈3.80 ms |
| FORS sign | ≈7.77 ms |
| FORS verify | ≈71 µs |

These are single-run integer microsecond values and are coarser than the
main benchmark. They are useful for attributing cost, not for precise
comparison.

## 6. Timing smoke test

The harness computes Welch's t-statistic for KEM decapsulation over
interleaved valid and tampered inputs at five ciphertext positions. With
`n = 10000`:

| Spot | `t` |
|---|---:|
| `c1[0]` | 0.025 |
| `c1[320]` | -0.545 |
| `c2[0]` | 0.737 |
| `c2[80]` | 0.154 |
| `ct[last]` | 0.391 |

The harness’s informational bar is `|t| > 4.5` at `n >= 10000`; no spot
crossed it. This is **not** a `dudect`-grade evaluation. It uses a small
number of spots, no machine-learning distinguisher, no randomized
interleaving at the granularity used by `dudect`, and no control for
frequency scaling, cache state, or compiler variation. Treat it as a
smoke test only.

## 7. Correctness and validation summary

| Gate | Result |
|---|---|
| Debug test suite | **146/146** |
| Release test suite | **146/146** |
| MSRV 1.70 test suite | **146/146** |
| Red-team defaults | **14/14 suites** |
| Red-team failure sweep, 20,000 trials | **20,000/20,000** clean |
| Red-team full ciphertext-bit sweep (one test ct) | **11,520/11,520** change `ss` |
| Lattice lab | **5/5 checks** |
| Cross-architecture KAT | **234,114 bytes identical** |
| KAT SHA-256 | four files match §4 of the test plan |
| KEM Miri | 9/9, 13,213.79 s |
| AEAD Miri | 6/6, 214.46 s |
| DS bounds Miri | 3/3, 0.42 s |

The Miri subset does not include full DS signing. The test count and
Miri details are in [testplan.md](testplan.md).

## 8. Benchmark limitations

- **Not a side-channel result.** The t-test is a smoke signal. The
  project has no power, EM, or fault laboratory data.
- **Not portable.** Scalar schoolbook arithmetic, no SIMD, no NTT, and
  a single CPU model. Different compilers, CPUs, and frequencies will
  produce different numbers.
- **Not production capacity planning.** The benchmark uses fixed
  messages, a warm cache, and a single process.
- **Not a security metric.** Faster code is not safer code. A slower
  path can still leak through branches or memory access.
- **Integer truncation.** Sub-microsecond values are rounded down by
  integer division; the 1 KiB seal/open values are at the resolution
  limit.
- **No statistical confidence intervals.** The controlled run reports
  point estimates and medians, not confidence bounds.
- **No energy measurement.** The project does not report joules per
  operation.

## 9. Reproducing the record

The minimum reproduction is:

```bash
git checkout c14169edd8c5cf520150c3b872f03f2237b244ac
cargo test --workspace --locked
cargo test --workspace --locked --release
cargo +1.70 test --workspace --locked
cargo run -q -p hypg-redteam
cargo run -q -p hypg-lattice
HYPG_BENCH_ITERS=8 HYPG_BENCH_DS_ITERS=8 HYPG_BENCH_TTEST_N=10000 \
  cargo run -q --release -p hypg-bench
```

For the KAT cross-check, follow
[testplan.md](testplan.md#41-cross-architecture-equality). For the Miri
subset, follow [testplan.md](testplan.md#7-miri-evidence). No result in
this document should be cited as an external validation.
