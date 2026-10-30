# Deployment posture and operational requirements

**Status: do not deploy.** HypG v2.0 is an unaudited research
prototype. It is not production-ready, not NIST-compliant, not
certified, and not covered by a security proof or external audit. This
document explains the operational requirements that would apply if a
future, independently reviewed system were derived from this code. It
is not approval to deploy the current code.

## 1. Why the current release is not deployable

The blockers are structural, not a matter of configuration:

- the KEM's lattice hardness is unconfirmed and its FO variant is
  unproven;
- the signature composition is unproven and has no signing-volume bound;
- the AEAD composition is unproven for this exact instantiation;
- there is no external audit, formal verification, or standards
  validation;
- there is no `dudect`-grade timing evaluation or power/EM/fault
  campaign;
- key storage, RNG, nonce management, and protocol framing are caller
  responsibilities;
- the CLI is operator tooling, not a hardened key-management product.

No combination of build flags changes those facts.

## 2. Caller responsibilities

If this code is used in a research harness, the caller must still
provide the following.

### 2.1 Randomness

- Use a CSPRNG with at least 256 bits of entropy for KEM `keygen` seeds.
- Use a fresh 32-byte CSPRNG output for every `encaps` call. The
  `coins` argument is the FO message itself; reusing it repeats the
  ciphertext and shared secret.
- Use a fresh 12-byte nonce for every AEAD message under a key.
  Nonce reuse breaks confidentiality.
- Use a fresh 32-byte `esk` for each DS key.
- Do not derive any of these values from passwords, timestamps,
  counters, or low-entropy identifiers.

The libraries do not include an RNG. The CLI reads `/dev/urandom`; that
is an OS facility and is not a NIST DRBG.

### 2.2 Key storage

- Store secret keys in memory protected from other processes.
- Use OS memory locking (`mlock`/`mlockall`) if the threat model includes
  swapping; the `no_std` libraries cannot do this.
- Restrict key files to the minimum necessary permissions.
- Do not pass secrets as command-line arguments in a real system; the
  CLI accepts them for reproducibility, and the OS may expose them in
  process listings or shell history.
- Treat `seed_copy`, `fake_copy`, `public_copy`, and caller buffers as
  secret copies that must be erased by the caller.
- Do not rely on `Drop` zeroization as secure deletion from physical
  media or from a compromised process.

### 2.3 Protocol framing

The library returns cryptographic objects, not a complete protocol.
A protocol must define:

- how public keys, ciphertexts, signatures, and tags are encoded and
  bounded;
- how the KEM shared secret is confirmed (implicit rejection gives no
  error);
- how AEAD nonces are assigned and transmitted;
- how associated data is bound to the message and context;
- how signatures are domain-separated by application and context;
- how replay, reflection, truncation, and reordering are prevented;
- how keys are rotated, revoked, and separated by role;
- how failures are logged without leaking secrets.

### 2.4 KEM key confirmation

Because `decaps` never fails, a protocol must not treat a returned
32-byte value as proof of a valid ciphertext. It must authenticate a
subsequent message, derive a session key with a transcript hash, or use
another explicit confirmation mechanism. The confirmation must not
create an oracle that reveals whether the KEM ciphertext was valid
before authentication completes.

### 2.5 AEAD nonce management

Use one of:

- a random 96-bit nonce with a collision budget appropriate to the
  message volume (the birthday bound is not zero);
- a counter or deterministic construction with a unique key per epoch;
- a protocol-level nonce derivation bound to sender, receiver, and
  message sequence.

Never reuse a nonce under a key. The library cannot detect reuse.

### 2.6 Signature context and volume

- Bind the application/context into the signed message or a protocol
  envelope. HypG-DS has no built-in context string beyond the digest
  domains.
- Choose and enforce a maximum number of signatures per key. FORS is
  few-time; the library enforces no limit.
- Decide whether deterministic signatures are acceptable. Same
  `(sk,msg)` returns the same signature.
- Do not treat exact-length and zero-padding checks as a SUF-CMA proof.

### 2.7 Streaming AEAD

- Do not parse, display, execute, or transmit tentative plaintext before
  `StreamOpener::finish` returns `Some(())`.
- On failure, discard the stream and the entire output buffer history.
- Do not reuse a poisoned stream.
- Remember that `finish` can only zeroize the buffer it is given; copies
  made during `update` are the caller's responsibility.

## 3. Misuse table

| Misuse | Consequence |
|---|---|
| Reusing KEM `coins` under one `pk` | Identical ciphertext and `ss`; loss of semantic security. |
| Using a low-entropy `seed` or `esk` | Guessable keys; total compromise. |
| Reusing an AEAD `(key,nonce)` | Keystream reuse; plaintext XOR leakage; tag forgery may become easier. |
| Releasing tentative streaming plaintext | Unauthenticated data is consumed. |
| Treating KEM `ss` as authenticated without confirmation | Active attacker may cause a mismatch that the protocol ignores. |
| Signing unboundedly under one DS key | FORS/WOTS security degrades; exact bound unanalysed. |
| Using one key for KEM and signatures | Cross-protocol key reuse; no domain separation at the key level. |
| Ignoring `None`/`false` | Accepts forged AEAD or signatures. |
| Logging secret keys or `ss` | Compromise via logs, crash dumps, or telemetry. |
| Passing secrets on the CLI | Process listing, shell history, and audit logs. |
| Assuming `forbid(unsafe_code)` means constant-time | Compiler and microarchitecture effects remain. |
| Assuming KATs are a security proof | They only pin bytes for fixed inputs. |

## 4. Build and platform notes

The cryptographic libraries are `no_std`, zero-external-dependency, and
`forbid(unsafe_code)`. They have been built for x86-64, aarch64, wasm32,
and checked for s390x. The KAT set is byte-identical on x86-64 and
`qemu-aarch64` musl. Native ARM64 and s390x runtime validation are not
part of the evidence.

`hypg-mt` and the CLI require `std`. The threaded signer uses scoped
threads and a 64-worker cap; worker count can be set with
`HYPG_MT_WORKERS` in `[1,64]` for testing. This environment variable is
not a security control.

Build profiles:

- release uses fat LTO, one codegen unit, `panic=abort`, and stripped
  binaries;
- debug assertions and tests are not a production configuration;
- no CPU-specific SIMD path exists; codegen may still use baseline
  instructions chosen by the compiler.

Do not enable `-C target-cpu=native` for a distributed binary unless the
deployment fleet is homogeneous and the build is reproducible.

## 5. Operational checklist for a future reviewed system

This checklist is not satisfied by the current release.

- [ ] Independent audit completed and findings closed.
- [ ] Lattice-estimator result published for the exact parameters.
- [ ] Decapsulation failure bound proven and measured.
- [ ] DS signing-volume bound chosen, documented, and enforced by the
      protocol.
- [ ] `dudect`-style timing evaluation completed.
- [ ] Power/EM/fault evaluation completed if the threat model requires
      it.
- [ ] Key storage and RNG integrated with an approved mechanism.
- [ ] Protocol framing, nonce management, replay protection, and key
      confirmation specified and reviewed.
- [ ] Fuzzing and parser robustness campaign completed.
- [ ] Incident-response and key-rotation procedures defined.
- [ ] Claims and documentation updated to match the review.

## 6. Current allowed use

The only defensible current uses are:

- cryptographic research and teaching;
- reproducibility studies;
- test harnesses and CI;
- comparative benchmarking;
- preparation for external review.

Any use that protects real confidential data, authenticates real
transactions, or issues real signatures is outside the current security
posture. If you are unsure whether a use is in scope, it is not.
