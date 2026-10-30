# Audit preparation and open technical questions

**Status:** preparation only. No external audit has been performed.
Nothing in this document is an audit finding, a certification, or a
statement of production readiness.

The purpose of this file is to make an independent review efficient: it
names the scope, the exact artifacts, the claims to attack, the evidence
that exists, and the evidence that does not.

## 1. Audit scope

An auditor should review the following, in order of risk.

1. **KEM composition.** Module-LWE encryption, the exact FO-style
   transform, implicit rejection, `H(pk)` binding, ciphertext binding,
   and the claimed failure behaviour.
2. **Decapsulation correctness.** The noise plus compression analysis,
   the `~14.6 sigma` working estimate, and the absence of a formal tail
   bound.
3. **DS composition.** FORS, WOTS+, XMSS, hypertree indexing, digest
   split, deterministic randomizer, reserved-byte encoding, and the
   signing-volume bound.
4. **Domain separation.** Every string and tag in
   [domains.md](domains.md), including the v2.0.1 `PRF`/`F` tags and the
   L-tree odd-node promotion.
5. **AEAD composition.** ChaCha20 + keyed-BLAKE3 EtM, key schedule, MAC
   input, nonce discipline, streaming tentative-plaintext semantics.
6. **Constant-time claims.** Source-level branchlessness, compiler
   behaviour, and the lack of `dudect`/power/EM evidence.
7. **Memory and secret lifetime.** Redacted `Debug`, non-`Copy` secret
   types, `Drop` zeroization, best-effort caveats, and copies returned
   by accessors.
8. **Failure paths.** Panics, out-of-range indices, length confusion,
   malformed keys, CLI exit codes.
9. **Portability.** Little-endian assumptions, `no_std`, target builds,
   cross-architecture KAT equality, and stack usage.

Out of scope for this repository: a production protocol, key management,
HSM integration, network security, and operational deployment.

## 2. Artifacts to provide

| Artifact | Location or command |
|---|---|
| Exact commit | `git rev-parse HEAD` |
| Working tree status | `git status --short` |
| Toolchain | `rustc --version`, `cargo --version` |
| Lockfile | `Cargo.lock` |
| Parameter constants | `crates/*/src/params.rs` |
| KEM spec | `docs/spec.md` |
| DS spec | `docs/spec-ds.md` |
| AEAD specs | `docs/spec-symm.md`, `docs/spec-aead.md` |
| Hash spec | `docs/spec-hash.md` |
| Domain registry | `docs/domains.md` |
| Threat model | `docs/threat-model.md` |
| Test evidence | `docs/testplan.md` |
| Performance evidence | `docs/metrics.md` |
| Frozen KATs | `crates/hypg-kat/kats*/` |
| KAT checksums | `docs/parameters.md` §6, `docs/testplan.md` §4 |
| GitHub workflow | `.github/workflows/ci.yml` |
| Miri workflow | `.github/workflows/nightly-miri.yml` |

## 3. Reproducibility commands

```bash
git status --short
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo test --workspace --locked --release
cargo +1.70 test --workspace --locked
cargo run -q -p hypg-redteam
cargo run -q -p hypg-lattice
cargo test -p hypg-kat --lib --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit
```

Cross-architecture and portability checks are in
[testplan.md](testplan.md). The KAT checksums are in
[testplan.md](testplan.md#4-frozen-kat-checksums).

## 4. Claims to attack

An auditor should not accept the following without independent analysis.
Some are claims the project makes; others are natural inferences a
reader might draw. Both are included so that the non-claims are tested
as carefully as the claims.

### 4.1 KEM

- **Claim:** the FO-style transform is IND-CCA2.
  **Question:** does the exact `ss = KDF(m || ct || H(pk))` and
  `reject = KDF(fake || ct)` construction satisfy a published FO
  theorem? What are the changes to the proof?
- **Claim:** the decapsulation failure probability is negligible.
  **Question:** derive a rigorous tail bound for
  `N_0 + Delta2 - <s,Delta1>`. Is the `~14.6 sigma` estimate meaningful
  for 256 coefficients and realistic query counts?
- **Claim:** `G(m,pk)` binds the ciphertext to the public key.
  **Question:** can a malformed `pk` or non-canonical packed coefficient
  create a cross-key collision or a re-encryption ambiguity?
- **Claim:** implicit rejection removes the validity oracle.
  **Question:** does the returned value have the right distribution,
  and does the protocol-level use of `ss` preserve CCA security?
- **Claim:** the CA-PRF is a safe expander.
  **Question:** if the outer BLAKE3 is a random oracle, is the CA
  irrelevant to security? If BLAKE3 is weakened, does the CA help at all?
  The documentation treats it as a design hedge, not a proven add-on.

### 4.2 DS

- **Claim:** the signature is UF-CMA for the intended signing volume.
  **Question:** derive the FORS/WOTS+/XMSS bound for this exact
  `(h,d,h',k,a,w)`, BLAKE3 tweakable hash, and deterministic `R`.
- **Claim:** stateless signing is safe without a state limit.
  **Question:** what is the maximum number of signatures per key before
  FORS leaf reuse or XMSS leaf reuse becomes unacceptable? The code
  enforces no limit.
- **Claim:** the reserved zero bytes prevent malleability.
  **Question:** are there other ignored or non-canonical fields? Is
  SUF-CMA actually achieved?
- **Claim:** deterministic signatures are acceptable.
  **Question:** what privacy/fault-injection properties are lost, and
  does the protocol require hedged signatures?
- **Claim:** the v2.0.1 PRF/F tags remove the structural collision.
  **Question:** are there any remaining 65-byte input collisions, and is
  the `H` arity separation sufficient?

### 4.3 AEAD

- **Claim:** the EtM composition is IND-CPA and INT-CTXT.
  **Question:** provide a reduction or cite a theorem covering
  ChaCha20 + keyed BLAKE3 with this exact key schedule and MAC layout.
- **Claim:** the streaming API is byte-identical to one-shot.
  **Question:** verify the partial-block, counter, and length accounting
  under adversarial chunking and exhaustion.
- **Claim:** the tentative-plaintext rule is sufficient.
  **Question:** can a caller accidentally release plaintext before
  `finish`? The API cannot enforce this.
- **Claim:** the 256-bit tag gives 256-bit integrity.
  **Question:** what is the actual forgery bound under the PRF
  assumption, and how does it interact with nonce reuse?

### 4.4 Implementation

- **Claim:** source-level branchlessness implies constant-time.
  **Question:** inspect compiled code for secret-dependent branches,
  memory indices, and variable-latency instructions.
- **Claim:** `forbid(unsafe_code)` implies memory safety.
  **Question:** confirm there are no external dependencies containing
  unsafe code, and no logic-level out-of-bounds via safe indexing.
- **Claim:** best-effort zeroization is adequate.
  **Question:** identify copies that escape (`seed_copy`, `fake_copy`,
  `public_copy`, caller buffers, thread stack, panic paths).
- **Claim:** panic-free public APIs.
  **Question:** check arithmetic overflow, slice indexing, and
  `debug_assert!` paths in release and debug.

## 5. Evidence that exists

- Source-inspection of all cryptographic crates (E0).
- 146 deterministic tests in debug, release, and MSRV (E1).
- Frozen KATs with SHA-256 checksums and cross-architecture equality
  (E1/E3).
- 14-suite deterministic red-team harness, including panic and
  secret-key-flip sweeps (E2).
- Local lattice lab validating toy breaks and computing a coarse
  real-parameter gap (E2).
- Miri on KEM 9/9, AEAD 6/6, and DS bounds 3/3; not full DS (E3).
- Release benchmark with timing-smoke t-test (not a side-channel
  evaluation).
- CI gates for formatting, clippy, docs, audit, zero external dependencies,
  `no_std`, stack size, cross-target builds, and KAT equality.

## 6. Evidence that does not exist

- External cryptanalysis or code audit (E4).
- Sage lattice-estimator result for the exact parameters.
- Analytic decapsulation-failure bound at `2^-128`.
- Formal constant-time proof or `dudect` evaluation.
- Power, EM, or fault-injection laboratory campaign.
- Formal verification or machine-checked proofs.
- Coverage-guided fuzzing campaign.
- Native ARM64/s390x runtime validation.
- NIST ACVP/CAVP/CMVP validation.
- Production key management, RNG, or protocol analysis.

## 7. Suggested auditor work plan

1. Read [threat-model.md](threat-model.md), [spec.md](spec.md), and
   [spec-ds.md](spec-ds.md) against the source.
2. Recompute the size and wire-layout tables from constants.
3. Re-run the deterministic gates and compare KAT checksums.
4. Attack the FO variant and the decapsulation-failure analysis first;
   these are the highest-risk unproven claims.
5. Attack the DS signing-volume and deterministic-randomizer choices.
6. Inspect compiled code for timing leakage; design a `dudect`-style
   experiment if resources permit.
7. Attempt malformed-input and parser fuzzing, including keys and
   signatures, not just ciphertexts.
8. Report findings with severity, exploitability, and the exact
   assumption affected.

## 8. Exit criteria for an audit-ready claim

The project should not describe itself as audited until:

- a named independent party has performed the review;
- the scope and commit hash are public;
- findings and remediations are published;
- the remaining risks are accepted in writing;
- the claims in [threat-model.md](threat-model.md) are updated to match
  the review.

No such review has occurred.
