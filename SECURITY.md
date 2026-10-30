# Security policy and posture

## Status

**HypG v2.0 is a research prototype. It is unaudited, unvalidated, and
not production-ready. Do not use it to protect real keys, messages, or
signatures.**

The workspace version is `2.0.0`. The active signature wire/spec
revision is **2.0.1**. The KEM, Symm, and Hash wire revisions are
2.0.0. Parameter dimensions resemble NIST Category-5 profiles, but this
is **not** a security certification, a NIST compliance claim, or a
bit-security claim.

Specific non-claims:

- The KEM's lattice hardness is unconfirmed; no lattice-estimator
  result for HypG exists.
- The KEM's exact FO-style transform has no published proof.
- The DS composition has no exact UF-CMA/SUF-CMA proof and no
  signing-volume bound. FORS is few-time; the code enforces no limit.
- The AEAD composition is not a standardized algorithm and has no
  nonce-misuse resistance.
- The `~14.6σ` decapsulation margin is a working estimate, not a formal
  failure bound.
- There is no external audit, formal verification, or coverage-guided
  fuzzing campaign.
- There are no power, electromagnetic, or fault-injection laboratory
  results; the timing smoke test is not a `dudect`-grade evaluation.
- There is no FIPS 140-3 validation, CMVP certificate, or ACVP/CAVP
  validation.

Read [docs/threat-model.md](docs/threat-model.md),
[docs/nist-alignment.md](docs/nist-alignment.md), and
[docs/audit-prep.md](docs/audit-prep.md) before making any security
statement about this repository.

## Reporting a security issue

There is no bug-bounty program and no guaranteed response time. This is
a research project. If you believe you have found a security-relevant
defect, open a GitHub issue with enough detail to reproduce it, or
contact the repository owner through the address published on the
repository profile.

A useful report includes:

1. the exact commit hash (`git rev-parse HEAD`);
2. the target triple and toolchain version;
3. a minimal reproducer or test;
4. observed versus expected behaviour;
5. the affected component and version;
6. whether the issue affects a frozen invariant, a security claim, or
   only performance/robustness.

Please do not include real secret keys, private user data, or
production credentials in a public issue.

## Scope

The highest-value review areas are:

- the exact KEM transform and implicit-rejection construction;
- the decapsulation failure analysis and compression residuals;
- the DS FORS/WOTS+/XMSS composition, deterministic randomizer, and
  signing-volume bound;
- the v2.0.1 `PRF`/`F` tags and L-tree odd-node promotion;
- the AEAD EtM composition and streaming plaintext semantics;
- constant-time claims and best-effort zeroization;
- malformed-key/signature handling and panic freedom.

Out of scope for this repository: a production protocol, key storage,
HSM integration, network security, and operational deployment.

## Frozen invariants

The following are treated as bugs if broken:

- KAT files must match byte-for-byte for the active versions.
- Signing is deterministic in `(sk,msg)` and `ds_verify` accepts its own
  output.
- KEM `encaps`/`decaps` round-trip on honestly generated inputs.
- `decaps` does not panic on correctly sized ciphertexts.
- AEAD one-shot `open` does not write plaintext before tag verification.
- Streaming AEAD output is byte-identical to one-shot for the same
  chunks.
- Changing a wire format without a version bump and new KAT files.

A failed invariant should be reported even if the current test suite
passes.

## Disclosure

There is no formal embargo process. For a serious issue, coordinate
privately with the repository owner before publishing exploit details
so that a fix and an honest advisory can be prepared. Do not represent a
fix as an audit or a production-readiness statement.

## Roadmap to any security claim

1. Run the community lattice-estimator on the exact `q=4096, k=4`
   parameters and publish the cost tables.
2. Derive an analytic decapsulation-failure bound and measure at least
   `10^6` trials.
3. Obtain independent review of the FO variant, the DS composition and
   signing-volume bound, and the role of `CA-PRF`.
4. Complete `dudect`-style timing evaluation and, if required, power/EM/
   fault evaluation.
5. Add coverage-guided fuzzing and a protocol-level misuse analysis.
6. Commission a third-party audit.
7. If FIPS compliance is required, redesign around approved primitives
   and pursue ACVP/CAVP and CMVP validation.

Until those steps are complete, the only appropriate use is research,
teaching, reproducibility, and test harnesses.
