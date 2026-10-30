# Design and rationale

**Status:** research prototype; unaudited; not production-ready. This
document explains why the implementation is shaped the way it is. It is
not a security proof.

## 1. Design constraints

HypG is built around five explicit constraints.

1. **No external dependencies.** Every dependency in the workspace is a
   local path dependency on another workspace crate. Primitive
   implementations are local and auditable in one tree.
2. **No `unsafe`.** Every library crate uses `#![forbid(unsafe_code)]`.
   Conversion and arithmetic paths are total where possible. The cost is
   slower scalar code and best-effort rather than volatile zeroization.
3. **`no_std` cryptographic libraries.** `hypg-core`, `hypg-kem`,
   `hypg-symm`, `hypg-aead`, `hypg-ds`, and `hypg-hash` do not require
   an allocator, a filesystem, or an operating system. `hypg-mt`, the
   CLI, and the evaluation harnesses are `std` crates.
4. **Fixed public geometry.** All loops over protocol objects have
   public bounds. Secret-dependent branches and array indices are
   avoided in the cryptographic paths.
5. **Reproducible evidence.** Deterministic KAT files, a local
   adversarial harness, a local lattice lab, cross-architecture equality
   checks, and a documented benchmark are part of the release.

These constraints do not imply side-channel security, production
quality, or standards compliance. They describe engineering choices.

## 2. System architecture

```text
                   +-----------------------------+
                   |        hypg-core            |
                   | BLAKE3 | ChaCha20 | CA-PRF  |
                   | R_q arithmetic | ct helpers |
                   +--------------+--------------+
                                  |
          +-----------------------+-----------------------+
          |                       |                       |
   +------v------+         +------v------+         +------v------+
   |  hypg-kem   |         |  hypg-symm  |         |  hypg-ds    |
   | Module-LWE  |         | one-shot    |         | FORS/WOTS+/ |
   | FO KEM      |         | EtM AEAD    |         | XMSS        |
   +------+------+         +------+------+         +------+------+
          |                       |                       |
          |                +------v------+         +------v------+
          |                |  hypg-aead  |         |  hypg-mt    |
          |                | streaming   |         | threaded    |
          |                +-------------+         +-------------+
          |
   +------v------------------------------------------------------+
   | hypg-hash (API) | hypg-kat (frozen vectors) | harnesses    |
   +-------------------------------------------------------------+
```

The dependency direction is acyclic. `hypg-core` does not depend on any
protocol crate. `hypg-aead` reuses the `hypg-symm` key types and wire
construction rather than defining a second AEAD. `hypg-mt` depends on
`hypg-ds` but the reverse is forbidden, which keeps threading out of the
`no_std` boundary.

## 3. Why Module-LWE with a power-of-two modulus

The KEM uses Module-LWE:

```text
b = A*s + e,
c1 = A^T*r + e1,
c2 = <b,r> + e2 + Encode(m),
```

with `n = 256`, `k = 4`, `q = 4096`, and `CBD(2)` secrets and errors.

The module rank 4 gives lattice dimension 1024, matching the dimension
of ML-KEM-1024 and the intended Category-5 parameter profile. The
power-of-two modulus permits branchless mask-only reduction and simple
packing. It is a deliberate deviation from ML-KEM's `q = 3329`, and it
changes the lattice hardness profile. No ML-KEM-1024 security estimate
is assumed to transfer.

The alternative `q = 3329` would permit closer comparison to ML-KEM but
would require Barrett or Montgomery reduction and would not preserve the
implementation's simple mask-only arithmetic. The project chose
transparent arithmetic over false equivalence with a standardized
parameter set. The consequence is that external lattice estimation is
mandatory before any security claim.

The implementation uses schoolbook negacyclic multiplication rather than
an NTT. This is slower but simpler to review, has no precomputed tables,
and avoids a large body of indexing and twiddle-factor code. The
performance target is evaluation and research, not high-throughput
server cryptography.

## 4. FO transform and implicit rejection

The KEM is a Fujisaki-Okamoto-style transform with implicit rejection.

- `Encaps(pk, m)` uses the 32-byte `m` both as the PKE message and as the
  seed input to the deterministic randomness generator
  `G(m, pk) = (r, e1, e2)`.
- The ciphertext is `PKE.Enc(pk, m; G(m,pk))`.
- The shared secret is `KDF(m, ct, H(pk))`.
- `Decaps` decrypts to `m'`, re-encrypts under `G(m', pk)`, and compares
  the resulting ciphertext with the received one in constant time.
- If the check fails, `Decaps` returns
  `KDF(fake, ct)` rather than an error. The `fake` value is fixed in the
  secret key and is pseudorandom to anyone without `sk`.

The design goals are:

1. **No public failure oracle.** A caller cannot distinguish a valid
   ciphertext from an invalid one by looking for an error return; both
   paths return 32 bytes.
2. **Ciphertext binding.** `G` is bound to the full public key, so the
   same `m` under a different `pk` produces different randomness and a
   different ciphertext.
3. **Shared-secret binding.** The accepted secret depends on `m`, the
   full ciphertext, and `H(pk)`. The rejected secret depends on the fake
   key and the full ciphertext.
4. **Uniform-path work.** Re-encryption, both KDF computations, and the
   constant-time select are performed on both accepted and rejected
   inputs at the algorithmic level. The code has no secret-dependent
   early return in `Decaps`.

This is an FO-style construction, not a byte-for-byte reproduction of a
standardized FO variant. In particular, the accepted secret is
`KDF(m || ct || H(pk))`, not simply `KDF(m)`, and the rejection value is
`KDF(fake || ct)`. A security proof would need to cover these exact
choices. No such proof has been published for HypG, and none is claimed
here. The construction should be treated as a well-motivated engineering
composition whose CCA security is conjectural pending review.

## 5. The CA-PRF expander

`CA-PRF` is a deterministic expander built from three stages:

```text
init  = XOF(seed || domain || "-init", 256)
rule  = XOF(seed || domain, 64)
state = CA^32(init; rule)
out   = XOF(domain || state || domain || "-out", L)
```

The cellular automaton is a 32-word state with a fixed hyper-graph
neighborhood (strides 1, 5, 17), a secret 8-word rule, and 32 rounds of
branchless XOR/AND/OR/NOT/rotate/multiply operations. All loop bounds are
public; all state and rule words are fixed-size stack arrays.

The outer BLAKE3 XOF is the security-relevant component. If BLAKE3 is a
secure XOF or random oracle, the output is computationally
indistinguishable from random regardless of the CA. The CA is therefore
best described as a **design hedge** and a domain-separated mixing stage,
not as an independently justified hardness assumption. This is an
important honesty point: the documentation does not claim that the CA
adds provable security on top of BLAKE3.

Why retain it at all? It provides a deterministic, branchless expansion
path that is shared by all secret derivations; it makes the
implementation's "hyper-graph automaton" design explicit; and it avoids
using a single hash call as the entire expander. Those are architectural
and defence-in-depth motivations, not a cryptographic proof.

The CA code uses only safe Rust. `State` and `Rule` redact `Debug` and
zeroize on drop. Temporary state is zeroized after each round.

## 6. Hash-based signatures

HypG-DS is a stateless hash-based signature scheme with the same
parameter shape as SLH-DSA-256f:

- 35 FORS trees of height 9;
- 17 XMSS layers of height 4 (total height 68);
- WOTS+ with `w = 16`, `len = 67`;
- a 256-bit hash output (`n = 32`).

A message digest selects FORS leaf indices, a 68-bit hypertree position,
and a 4-bit bottom leaf. FORS signs the digest; the hypertree signs the
FORS public key and then each lower root. The final signature is
stateless: no signing state is stored or advanced.

Statelessness was chosen over XMSS-MT because state management is a
common source of catastrophic key reuse in hash-based signatures.
Statelessness is not free: FORS is a few-time signature, so the security
bound degrades with the number of signatures produced under one key.
HypG does not enforce a signing limit. A deployment profile would need to
choose and enforce one, or rely on a multi-target security analysis that
accounts for the expected signing volume. This is an open analysis item,
not a property supplied by the code.

The scheme is **SLH-DSA-256f-shaped**, not SLH-DSA. It uses BLAKE3
instead of SHA-2 or SHAKE, a different 32-byte address layout, explicit
PRF/F tags, deterministic randomizer derivation, and 8 reserved bytes per
layer. It produces a 49,992-byte signature rather than FIPS 205's 49,856.
See [nist-alignment.md](nist-alignment.md).

Signing is deterministic in `(sk, msg)`. The randomizer is

```text
R = BLAKE3(CA-PRF(prf, "HYP-G/v07/ds-addrnd")[0..64] || BLAKE3(msg)).
```

There is no fresh per-signature entropy. Repeated signing of the same
message returns the same signature. This is intentional for
reproducibility and KATs, but it has privacy and fault-injection
consequences that a randomized profile would not have. The scheme is
not freshly hedged.

## 7. AEAD composition

The AEAD is Encrypt-then-MAC:

```text
(enc, mac) = (DK(".../symm-enc", K), DK(".../symm-mac", K))
ct         = ChaCha20(enc, nonce, counter=0, message)
tag        = KeyedBLAKE3(mac, nonce || ad || ct || LE64(ad_len) || LE64(ct_len))
```

ChaCha20 provides confidentiality; keyed BLAKE3 provides integrity. The
stream cipher never authenticates, and the MAC never encrypts. The tag is
checked before decryption in the one-shot `open`, so a forgery does not
release plaintext.

The construction is a standard EtM pattern but is not a standardized AEAD
algorithm. It has no nonce-misuse resistance: reusing a `(key, nonce)`
pair with different messages destroys confidentiality and can expose
relationships between messages. The caller is responsible for nonce
uniqueness. The 32-byte tag gives a large integrity margin, but no
proof for this exact composition is included.

The streaming front uses the same subkeys, the same MAC input, the same
ChaCha counter sequence, and the same tag. Only the scheduling differs.
This is why a separate frozen streaming KAT file is unnecessary: the
one-shot vectors are the canonical wire vectors, and streaming equality
is tested against them across adversarial chunk boundaries.

## 8. Threading

Threading is a platform capability, not a cryptographic primitive. The
`no_std` crates never spawn threads. `hypg-mt` uses `std::thread::scope`
and a fixed, strided assignment of independent tree builds. Because each
tree unit is a pure function of public geometry and `(pubseed, esk)`,
scheduling cannot affect the output. `mt_sign` is tested to be
byte-identical to `ds_sign`; the KATs therefore cover both.

The threaded signer allocates vectors for gathered units and boxes the
large hypertree signature. The `no_std` cryptographic libraries remain
allocation-free. This is a deliberate boundary: embedded users call the
serial signer and provide their own buffers; host users may opt into
`hypg-mt`.

## 9. Failure and error philosophy

HypG distinguishes three failure classes.

1. **Protocol rejection.** AEAD `open` returns `None`; DS verification
   returns `false`; these are public, caller-visible outcomes.
2. **Implicit rejection.** KEM `decaps` never fails. An invalid
   ciphertext produces a pseudorandom shared secret. Callers must use the
   secret in a protocol that detects mismatch (for example, by
   authenticating a subsequent message), not by expecting an error.
3. **Programming error.** Length mismatches, out-of-range indices, and
   malformed inputs fail closed or return `None`/zeroed outputs. Public
   APIs are designed not to panic on adversarial byte strings.

The design does not use exceptions or allocation failure paths in the
cryptographic libraries. `no_std` APIs return values or `Option<()>`; DS
signing writes into a caller-provided exact-size buffer.

## 10. What the design does not provide

HypG does **not** provide:

- a proof of IND-CCA2 security for the exact KEM transform;
- a proof of UF-CMA or SUF-CMA security for the exact DS composition;
- a proof of AEAD security for the exact EtM composition;
- a lattice-estimator result or a bit-security claim;
- a formal constant-time proof, compiler-barrier analysis, or
  `dudect`-grade timing evaluation;
- power, electromagnetic, or fault-injection resistance claims;
- protection against a compromised OS, allocator, compiler, or RNG;
- secure key storage, `mlock`, HSM integration, or side-channel-hardened
  arithmetic;
- NIST compliance, FIPS validation, or certification.

These are not minor caveats. They are the reason the project remains a
research prototype.
