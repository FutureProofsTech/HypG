# Changelog (HypG)

All notable changes. Format follows Keep-a-Changelog. The workspace
version is **2.0.0**; the active DS wire/spec revision is **2.0.1**.
This is a **hardened research profile** (breaking parameter change,
unaudited, do not deploy): KEM `k = 4`, DS `HypG-DS-256f`. The
`HYP-G/v07/...` domain strings and BLAKE3/ChaCha20 primitives are
unchanged. v1.0.0 remains a frozen historical release with its own KAT
files.

## [2.0.1] — 2026-10-30 — DS wire revision and audit hardening

Workspace version remains `2.0.0`. This entry records the DS wire
revision and the security-hardening pass committed as `c14169e`.

### Changed (DS wire revision)
- **Explicit PRF/F tags.** `PRF` now hashes
  `0x01 || seed || ADRS`; `F` hashes `0x02 || ADRS || x`. Before this
  revision both were 64-byte keyed-BLAKE3 inputs distinguished only by
  field order, permitting a structural collision when a secret seed
  happened to equal a public address.
- **L-tree odd-node promotion.** An unpaired final WOTS+ L-tree node is
  promoted unchanged (FIPS 205 style) instead of being hashed with
  itself. This changes every WOTS L-tree root, XMSS root, and signature.
- **New DS KAT.** `kats-ds/v2.0.1.txt` is the active gate; the v2.0.0
  DS vector file remains as historical evidence. KEM/Symm/Hash wire
  bytes are unchanged.

### Security hardening
- Secret types (`SecretKey`, `SharedSecret`, `SigSk`, `PreSign`, `Key`,
  `State`, `Rule`, `Hasher`, `Poly`, `Poly10`, `Poly5`) now redact
  `Debug`, avoid `Copy` where appropriate, compare in constant time where
  equality is exposed, and best-effort zeroize on `Drop`.
- `PreSign.esk` is private, exposed only through `PreSign::esk()`, and
  zeroized on drop.
- KEM keygen/encaps/decaps/derive-rand/PKE temporaries, WOTS/FORS/XMSS
  secrets, AEAD subkeys, ChaCha/CA temporaries, and threaded gather
  buffers are wiped.
- Out-of-range FORS, XMSS, and hypertree indices fail closed instead of
  wrapping or producing a zero-message signature.
- `fold.rs` helpers rewritten as total functions; `dot` is total on
  unequal lengths.
- AEAD `ct_len` uses checked addition; streaming failure paths zeroize
  the tag; the one-shot block-space boundary accepts exactly
  `MAX_MSG_LEN`.
- CLI flag parsing is strict: missing values, unknown extras, bad hex,
  and wrong lengths exit `2`; authentication failures exit `3`. Added
  25 negative integration tests.
- Symm `seal` clears ciphertext and tag on failure; `Key` is no longer
  `Copy`; constant-time equality and `Drop` zeroization added.

### Re-recorded evidence
- Debug, release, and MSRV 1.70 suites: **146/146** each.
- Red-team defaults: **14/14** suites. Fresh release runs:
  **20,000/20,000** failure trials clean; **11,520/11,520** bit positions
  of a test ciphertext change `ss`.
- Lattice lab: **5/5** checks.
- KAT cross-architecture: **234,114 bytes identical** on x86-64 and
  `qemu-aarch64`.
- Miri: KEM **9/9** (13,213.79 s), AEAD **6/6** (214.46 s), DS bounds
  **3/3** (0.42 s). Full DS signing is not covered.
- Controlled benchmark: KEM keygen/encaps/decaps **795/931/1124 µs**;
  DS sign/verify **72.009/3.725 ms**; threaded sign **18.329 ms**
  (3.928× at 16 workers); AEAD 1 MiB seal/open **427/434 MB/s**.
- Documentation rewritten: formal notation, parameter register, design
  rationale, API reference, normative KEM/DS/AEAD/hash specs, domain
  registry, threat model, test plan, metrics, NIST gap analysis, audit
  preparation, deployment posture, estimator work order, lattice lab,
  threading, and SIMD notes.

### Security note
This is still **not** an audit, a proof, or a NIST compliance claim.
The KEM lattice hardness is unconfirmed; the FO variant and DS
composition are unproven; the decapsulation failure bound, signing-volume
analysis, `dudect`-grade timing, and power/EM/fault evaluation remain
open.

## [2.0.0] — 2026-10-30 — hardened parameter profile

### Changed (breaking)
- **KEM parameter hardening**: module rank `k = 2 → 4` (lattice
  dimension 512 → 1024, NIST Category-5 dimensions). New sizes:
  `pk = 1568 B`, `ct = 1440 B`, `sk = 1632 B`, `ss = 32 B`.
  `dot2` generalized to `dot` for rank-4 vectors; matrix `A` is now
  `4×4`.
- **Signature parameter hardening**: `HypG-DS-128s` (`h=60`, `d=12`,
  `h'=5`, FORS `30×7`) replaced by `HypG-DS-256f` (`h=68`, `d=17`,
  `h'=4`, FORS `35×9`). New `sig = 49992 B`; `pk = 64 B`,
  `sk = 128 B` unchanged. The tree index widened to `u128` (12-byte
  `ADRS` field) and serialization now uses the parameter constants.
- **KAT re-freeze**: the 2.0.0 files are `kats*/v2.0.0.txt`; v0.4–v0.7
  files remain in the tree as historical evidence. The DS file was
  subsequently revised to `kats-ds/v2.0.1.txt` in the 2.0.1 entry above.
- **Workspace version** bumped to `2.0.0`; all crates and `Cargo.lock`
  updated.

### Added
- IACR-style research paper (`papers/iacr.tex`, LNCS class) by Dimitar
  Luchev (Independent Researcher), with LaTeX source tracked and the
  built PDF excluded.
- White Paper (`papers/whitepaper.tex`) and Yellow Paper
  (`papers/yellowpaper.tex`) updated for v2.0 parameters.
- Professional GitHub README with pillars, architecture, testing,
  performance, security boundary, and License sections.
- `docs/nist-alignment.md`: parameter mapping to FIPS 203/205 and an
  explicit gap analysis for NIST compliance and production use.
- `hypg-lattice` L4 check updated to the rank-4 dimension
  (`d = 2049`, `log2vol = 12288`).

### Changed
- License switched to **GPL-3.0-or-later** (`LICENSE`, workspace
  metadata); README documents the terms.
- Red-team S2 now sweeps all 11,520 bit positions of a test
  ciphertext; S11 checks all 17 DS layer pads.
- Bench re-recorded for v2.0 (initial sample; the controlled re-record
  is in the 2.0.1 entry): KEM 751/914/1107 µs, DS sign/verify
  45.7/2.25 ms (threaded sign 12.6 ms), AEAD 397/405 MB/s, hash
  818 MB/s, ChaCha20 754 MB/s.

### Security note
- Matching NIST Category-5 *dimensions* is not a security
  certification. Bit-security remains unconfirmed (no estimator run),
  and the signature composition is unreviewed. v2.0 remains
  **unaudited — do not deploy**.

## [1.0.0] — 2026-09-29 — frozen prototype

Freeze record: all five specs `FROZEN`, 129/129 tests green on stable
(debug + release) and MSRV 1.70, redteam 14/14 (max load: 20000/20000
failure sweep, 816 + 6400/6400 malleability flips, t-test max |t| ≈
1.23), Miri UB-clean (core/symm/kem), `cargo audit` clean, KATs
byte-identical x86-64/AArch64 and debug/release, 1 MB-stack run green.
Checklist executed: sizes/domains/APIs/KATs verified
(`docs/testplan.md`); `threat-model.md` + `audit-prep.md` signed off.
What 1.0 certifies is process completeness — not security (residual
risks: unconfirmed bit-security, no lab side-channels, no human audit).

### Added
- Phase 1 test-hardening: `hypg-cli` exit-code split (`2` usage/input
  error, `3` authentication failure for forged `ct`/`tag`/`sig`) with 20
  CLI failure-path integration tests (incl. garbage-`ct` implicit
  rejection at exit `0`); 7 runnable doc-tests on all public API pillars
  (`b3_hash`, KEM round-trip, AEAD seal/open + forgery, `ds_sign`,
  `mt_sign`, KAT renderers); extended CI hygiene gates (no
  `panic!`/`unreachable!`/`todo!`, no `unwrap`/`expect`, no heap types in
  `no_std` libs) + zero-dependency assertion; new `release-gates` CI job
  (`cargo test --release`, release redteam, debug/release KAT diff).
- `hypg-mt` is now panic-free: lost worker threads fall back to serial
  recomputation of the same chunk (identical bytes), and empty assembly
  slots are computed serially — the last `.expect()`s are gone.
- Phase 2 boundary tests: ChaCha counter-exhaustion (`0xFFFF_FFFE`,
  `u32::MAX`), `fits_block_space` edges, XMSS `idx` 0/31, FORS edge
  leaves 0/127, WOTS checksum extremes + nibble invariant, `split()`
  bit-exactness vector, AEAD nonce-reuse documentation, KEM encaps
  determinism.
- Phase 3 hardening: redteam `S12` panic sweep (1011-case deterministic
  corpus over all APIs) and `S13` `sk` bit-flip sweep (seed/`pk`
  corruption breaks the exchange; fake-key corruption is invisible on
  the honest path but diverges the reject output — oracle reflects the
  spare-key design); `S2` full-bit mode (`HYPG_REDTEAM_FLIPS=all`,
  6400/6400 verified); bench `ds_verify` valid/forged timing pair;
  `sizes_ok` invocation tests; poly commutativity/associativity;
  `caprf` length shapes; exhaustive 1-byte AEAD messages; CI now covers
  `hypg-mt` under x86-64-v3, 1 MB-stack KAT+redteam, wasm32 builds,
  s390x check + explicit-LE gate; new `docs/testplan.md` matrix and
  per-release checklist.
- Phase 4 final sweep: Miri UB-clean for `hypg-symm` (11/11) and
  `hypg-kem` (9/9, ~75 min — weekly scheduled CI, DS excluded with
  rationale); `cargo audit` clean (CI-gated); MSRV 1.70 fully verified
  (107/107 on the 1.70 toolchain, CI-gated; required one compat fix:
  inline-`const` → underscore-`const` in `poly.rs`); KAT
  second-message audit found all pillars already covered (no
  frozen-file churn); `metrics.md` re-recorded 2026-09-29.
- Phase 5 throughput proof: `hypg-bench` `big_1mib` lines (1 MiB,
  fixed reps, integer MB/s). Release: hash 796, streaming 834, XOF
  786, ChaCha 686, AEAD seal/open 372/375 MB/s — the >100 MB/s bar
  holds everywhere; numbers recorded in `metrics.md`.
- Phase 6 hashing pillar: new `hypg-hash` crate (thin `no_std` API over
  oracle-validated BLAKE3 — `hash32`/`hash64`/keyed/derive/expand/KDF,
  streaming equivalence, 9 unit + 3 doc-tests), frozen
  `kats-hash/v0.7.0.txt` (third-party cross-checked anchors),
  `docs/spec-hash.md`, CI coverage everywhere (v3, cross-builds, s390x,
  hygiene). No new cryptography by design.
- Phase 7 AEAD pillar: new `hypg-aead` crate (`StreamSealer`/`Opener`,
  incremental EtM wire-identical to `hypg-symm` — same subkeys/MAC
  order/counter sequence, buffered partial-block keystream, poison-on-
  error, redacted `Debug`, wiping `Drop`; 6 unit + 2 doc-tests),
  redteam `S14` (24 streaming games), `docs/spec-aead.md`. The
  equivalence tests caught one genuine keystream-skipping bug in
  development (counter restarted per chunk); fixed with cross-chunk
  block buffering. `hypg-core::chacha::block` exposed for streaming
  consumers (one new `pub`, no behavior change).

### Added
- Redteam `S11` mega-suite (burst faults, tampered-`pk` exchange break,
  garbage `sk`×`ct` matrix, 12/12 DS pad flips, multi-sign, 1 MiB AEAD);
  `S2` now also sweeps the last 16 ct bytes. Max-load record: 20000
  trials + 816 flips clean, t-test `n = 10000` max |t| ≈ 0.58.
- `docs/simd.md`: AVX2/NEON investigation record (no intrinsics under
  `forbid(unsafe)`, portable SIMD nightly-only, batch-4 negative result,
  ISA matrix, opt-in `target-cpu` flags). CI now builds+tests libs under
  `x86-64-v3`; `thumbv7em`/`wasm32` rlib builds verified locally.

### Added
- `hypg-mt`: scoped-thread parallel DS signing (`std`, zero-dep).
  12 XMSS + 30 FORS tree builds run on `available_parallelism()`
  workers (strided, `HYPG_MT_WORKERS` override); output byte-identical
  to serial across 1/2/64 workers (tested). Measured **5.5×** (65 ms →
  12 ms, 16 threads). Libs unchanged in behavior; new `pub` building
  blocks only (`xmss_build`, `xmss_sign_with_leaves`, `fors_sign_one`,
  `pre_sign`, `serialize_sig`).
- `hypg-bench` DS breakdown profiler (`HYPG_BENCH_PROFILE=1`): hash
  ns/op, `CA-PRF` vs KDF split, WOTS/XMSS-layer/FORS timings.
- `docs/threading.md`: model, determinism/safety arguments, sizing,
  deliberate non-goals.

### Changed
- `xmss_sign` reuses the signed leaf's WOTS secret instead of
  regenerating it (~0.2%, hygiene); auth path confirmed single-pass.
- PGO evaluated and rejected: reproducible ~2.6× slowdown
  (see `docs/metrics.md`); do not use.

## [0.7.0] — BLAKE3 + ChaCha migration (lattice + APIs unchanged)
### Changed
- Portable BLAKE3 (`hypg-core::b3`: hash, streaming XOF, keyed hash,
  `derive_key`; scalar safe Rust, oracle-validated vs official crate)
  replaces SHA3/Keccak everywhere; `hash.rs` and `duplex.rs` deleted.
- AEAD rebuilt as ChaCha20 + keyed-BLAKE3 Encrypt-then-MAC
  (`hypg-symm`): nonce is now 12 B, tags verify-then-decrypt with `pt`
  untouched on failure, subkeys via `derive_key`.
- DS tweak hashes use keyed BLAKE3 (`pubseed` as MAC key); all domains
  bumped `v03`/`v05` → `v07` (registry updated); all KATs re-frozen.
- Measured: DS sign ≈ 6× faster in debug; release re-measured below.

### Security
- 256-bit BLAKE3 outputs preserve the Grover-2¹²⁸ preimage story;
  duplex-AEAD bounds are replaced by standard EtM assumptions
  (stream confidentiality + MAC unforgeability). Still `0.x`: estimator,
  external review, and now a fresh review of the migration itself.

## [0.6.0] — signature pillar (KEM + Symm untouched, KAT-stable)

### Added
- `hypg-ds`: stateless hash-based signatures (`HypG-DS-128s`: FORS
  (30,7) + 12-layer XMSS/WOTS+ hypertree, `pk` 64 B, `sk` 128 B, `sig`
  35456 B); 12 unit tests (WOTS+ chains, XMSS, FORS, hypertree, SLH
  round-trip/tamper/determinism/zeroize).
- WOTS+ chains always execute all 15 steps with branchless `ct_select`
  (secret message digits never touch loop bounds — platinum intact).
- Reserved-index signature fields are zero-filled at sign and
  rejection-checked at verify (non-malleable).
- Frozen DS vectors `crates/hypg-kat/kats-ds/v0.6.0.txt` + byte-exact test.
- Redteam `S10` (sig/message/key flips reject, determinism); bench
  `ds_sign`/`ds_verify` throughput; CLI `ds-keygen`/`ds-sign`/`ds-verify`
  + CI smoke.

### Security
- Closed-form FORS/WOTS+/XMSS bounds cited, not confirmed; composition
  bound needs auditor confirmation. Still `0.x` overall.

## [0.5.0] — symmetric pillar (KEM untouched, KAT-stable)

### Added
- `hypg-symm`: keyed-duplex AEAD (`seal`/`open`, key 32 B, nonce 24 B,
  tag 32 B) + hash/XOF re-exports; 6 unit tests (rate-edge sweep,
  AD variants, tamper-reject with pt zeroization, determinism).
- `hypg-core::duplex`: shared sponge module (`r = 1088`, `c = 512`,
  128 B blocks, frame/pad/permute) with 5 unit tests; `keccak_f1600`
  shared `pub(crate)` instead of duplicated.
- Frozen AEAD vectors `crates/hypg-kat/kats-symm/v0.5.0.txt` + byte-exact test.
- Redteam `S9` (AEAD adversarial: 64 tag flips, ct/key/nonce/ad flips,
  empty-both, determinism); bench `seal/open` throughput + forged-tag
  timing smoke; CLI `seal`/`open`/`hash` commands + CI smoke.
- Docs: `spec-symm.md`, `spec-ds.md` (specified, unbuilt), `domains.md`
  registry. KEM `v03` domains frozen and KAT-pinned.

### Security
- AEAD targets 128-bit PQ from `c = 512` duplex bounds (heuristic, cited,
  unreviewed). Nonce discipline is the caller's. Still `0.x` overall.

## [0.4.0] — hardening + evidence (parameters/APIs stable since 0.3)

### Added
- `hypg-redteam`: 8-suite adversarial harness (garbage robustness,
  malleability sweep, 8×8 key-mismatch matrix, message extremes,
  FO binding, CBD sampler statistics over 524288 coeffs, failure sweep,
  determinism). CI-gated.
- `hypg-bench`: Welch t-test mode (`HYPG_BENCH_TTEST_N`) plus a
  5-position tamper sweep (`c1`/`c2`/last-byte); per-mille median ratio retained.
- `hypg-lattice`: local lattice lab — classical LLL with exactness tests,
  toy-LWE (`n = 8`, `q = 257`) end-to-end break (planted 59 → found 59),
  dense-lattice GH check (ratio 1.09), real-parameter gap analysis
  (`d = 1025`, gap 15.4×, LLL worst-case slack 2^508).
- `hypg-cli`: operator keygen/encaps/decaps with hex I/O and
  fail-closed `/dev/urandom` randomness; CI round-trip smoke test.
- `SecretKey::zeroize` / `SharedSecret::zeroize` (safe-Rust best effort).
- Frozen KAT file `crates/hypg-kat/kats/v0.4.0.txt` + byte-exact test.
- Docs: `deployment.md`, `metrics.md`, `estimator.md`, `audit-prep.md`,
  `docs/lattice-local.md`.

### Changed
- Threat model retires the `<256 B` target (incompatible with 128-bit PQ).
- Cross-arch runtime KAT proven locally (musl static + `qemu-aarch64`,
  15457 bytes identical); CI builds the static binary and diffs under
  qemu when present.

### Removed
- Dead `hypg_core::hash::sha3_parts` (zero callers; carried the only
  length-dependent branch in libs).

### Security
- Still `0.x`: lattice-estimator confirmation, `dudect`-grade timing,
  third-party audit outstanding. See `docs/estimator.md`.

## [0.3.0] — Module-LWE scale-up (`n = 256`, `k = 2`, `q = 4096`)

- `pk = ct = 800 B`, `sk = 864 B`; 1 bit/coeff encoding; `12→10`/`12→5`
  compression; `CA-PRF` randomness substrate; FO-KEM with implicit rejection.

## [0.2.0] — First real trapdoor (toy Ring-LWE, `n = 64`)

- Replaced the v0.1 public mask with Ring-LWE PKE + FO.

## [0.1.0] — Skeleton (insecure by design)

- NIST-style API shape, deterministic CA core, from-scratch SHA3-256,
  implicit-rejection plumbing, KAT harness. No IND-CPA (public mask).
