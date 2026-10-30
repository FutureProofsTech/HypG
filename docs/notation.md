# Notation and security definitions

**Status:** explanatory and normative for notation. This document does
not add a security claim beyond the one in
[threat-model.md](threat-model.md).

## 1. Bytes, integers, and encodings

| Symbol | Meaning |
|---|---|
| `{0,1}^n` | Bit strings of length `n`. |
| `{0,1}^*` | Finite bit strings. |
| `[a,b)` | Half-open integer interval `{a, ..., b-1}`. |
| `x[i]` | The `i`-th byte of byte string `x`, zero-based. |
| `x[a:b]` | Bytes `a` through `b-1`, inclusive of `a`, exclusive of `b`. |
| `A \|\| B` | Concatenation of byte strings. |
| `len(x)` | Length of `x` in bytes. |
| `LE_t(x)` | The `t`-bit unsigned integer `x` encoded as `t/8` bytes, least-significant byte first. |
| `0x...` | Hexadecimal literal. |
| `byte(i)` | The byte whose unsigned value is `i`, `0 <= i < 256`. |
| `repeat(b,n)` | `n` copies of byte `b`. |

Unless stated otherwise, multi-byte integers use little-endian byte
order. This is the normative convention for the KEM packing, the DS
address structure, the CA state, and the AEAD length suffixes. ChaCha20
uses the little-endian word loading of RFC 8439. BLAKE3 uses its
specified little-endian compression encoding.

A byte string is not implicitly padded. All hashes absorb exactly the
bytes listed in the relevant input expression. When a construction needs
unambiguous concatenation of variable-length fields, the protocol either
uses a fixed layout (all fields fixed length) or an explicit length
suffix. The AEAD MAC is the principal example of the latter:

```text
nonce || ad || ct || LE64(len(ad)) || LE64(len(ct)).
```

The KEM and CA-PRF inputs use fixed-length fields; their domain strings
are distinct ASCII constants.

### 1.1 Hex and text

Hex strings in this documentation are lowercase, without a `0x` prefix,
and encode bytes in order. Ellipses in a checksum mean that the middle
is omitted for readability; the complete value is in the named file.

ASCII domain strings are byte strings. For example,
`"HYP-G/v07/ss"` denotes the 12 bytes `48 59 50 2d 47 2f 76 30 37 2f
73 73`.

## 2. Rings and vectors

Let

```text
R_q = Z_q[X] / (X^256 + 1),    q = 2^12 = 4096.
```

An element of `R_q` is represented by its coefficient vector
`(a_0, ..., a_255)`, with `a_i` in `[0,q)`. Addition and subtraction are
coefficient-wise modulo `q`. Multiplication is negacyclic:

```text
(a*b)_k = sum_{i+j=k} a_i b_j - sum_{i+j=k+256} a_i b_j  (mod q).
```

The implementation uses the right-hand expression directly, with an
`i64` accumulator and a final low-12-bit reduction. Because `q` is a
power of two, reduction modulo `q` is a mask; no division or Barrett
reduction is used.

For module rank `k`, a vector is written `a = (a_0, ..., a_{k-1})` and

```text
<a,b> = sum_{i=0}^{k-1} a_i b_i  in R_q.
```

The KEM uses `k = 4`. Matrices are written `A = (A_{i,j})` with rows
indexed by `i` and columns by `j`.

### 2.1 Small distributions

`CBD(eta)` is the centered binomial distribution obtained from `4*eta`
independent uniform bits. For `eta = 2`, the implementation uses four
bits per coefficient:

```text
v = (b_0 + b_1) - (b_2 + b_3),   b_i in {0,1} uniform.
```

The support is `{-2,-1,0,1,2}` with probabilities

```text
Pr[-2] = 1/16, Pr[-1] = 4/16, Pr[0] = 6/16,
Pr[ 1] = 4/16, Pr[ 2] = 1/16,
```

mean `0`, and variance `1`. Coefficients are mapped to `[0,q)` by adding
`q` and masking. The 128-byte input to `CBD(2)` supplies exactly
`256 * 4` bits.

`U(R_q)` denotes the uniform distribution on `R_q`, represented by 384
uniform bytes unpacked as 12-bit coefficients. `U({0,1}^{256})` is the
uniform distribution on 32-byte strings.

## 3. Hash and expander notation

The following functions are used throughout the specifications.

| Notation | Concrete instantiation |
|---|---|
| `H(x)` | Unkeyed BLAKE3-256 of `x`; 32-byte output. |
| `H_k(x)` | Keyed BLAKE3-256 with 32-byte key `k`; 32-byte output. |
| `XOF(x, L)` | First `L` bytes of the BLAKE3 XOF applied to `x`. |
| `XOF_D(domain, parts, L)` | First `L` bytes of `XOF(domain \|\| parts..., ...)`. |
| `DK(context, key)` | BLAKE3 `derive_key(context, key)` with a 32-byte key and 32-byte output. |

`CA-PRF(seed, domain)` is the deterministic expander defined in
[spec.md](spec.md#22-ca-prf). It is not an additional hardness assumption:
its final stage is BLAKE3 in XOF mode, so any security argument that
treats BLAKE3 as a random oracle or secure XOF already covers the
expander output. The cellular-automaton stage is a design hedge, not a
proven independent primitive.

For a domain string `d`, write `d_init = d || "-init"` and
`d_out = d || "-out"`. The exact CA-PRF construction is

```text
init  = XOF(seed || d_init, 256)
rule  = XOF(seed || d, 64)
state = CA^32(init; rule)
out   = XOF(d || state || d_out, L).
```

The `CA^32` operation is specified in [spec.md](spec.md#22-ca-prf). All
three inputs use fixed-length components except the public domain string,
which is a compile-time constant at every call site.

## 4. Security definitions

The following standard definitions are used only to state the intended
targets. They are not proofs, and none of them has been established for
HypG by an external party.

### 4.1 KEM

A key-encapsulation mechanism is a triple

```text
KeyGen() -> (pk, sk),
Encaps(pk) -> (ct, K),
Decaps(sk, ct) -> K',
```

with `K, K'` in `{0,1}^32`.

**IND-CCA2.** For every probabilistic polynomial-time adversary `A` with
a decapsulation oracle, the advantage

```text
Adv^{IND-CCA2}_KEM(A)
  = |Pr[b' = b] - 1/2|
```

is negligible, where the challenger runs `(pk,sk) <- KeyGen()`, gives
`pk` to `A`, computes `(ct*,K_0) <- Encaps(pk)`, sets `K_1` uniform,
gives `(ct*,K_b)` for a hidden bit `b`, and answers decapsulation queries
for `ct != ct*`.

**Implicit rejection.** On an invalid ciphertext, `Decaps` returns a
pseudorandom value rather than a distinguished error. This avoids a
public failure oracle but is not by itself a substitute for a CCA proof.

### 4.2 Digital signature

A signature scheme is a triple

```text
KeyGen() -> (pk, sk),
Sign(sk, m) -> sigma,
Verify(pk, m, sigma) -> {0,1}.
```

**UF-CMA.** For every probabilistic polynomial-time forger `F` with a
signing oracle, the probability that `F` outputs `(m*, sigma*)` with
`m*` never queried and `Verify(pk,m*,sigma*) = 1` is negligible.
**Strong unforgeability (SUF-CMA)** additionally forbids a new signature
on a previously queried message.

HypG-DS is deterministic. Determinism does not imply strong
unforgeability; the reserved zero padding and exact-length check are
intended to remove trivial encoding malleability, but no SUF-CMA proof
exists for this composition.

### 4.3 AEAD

An AEAD scheme is a pair

```text
Seal(K, N, AD, M) -> (C, T),
Open(K, N, AD, C, T) -> M or error.
```

**IND-CPA** and **INT-CTXT** are the expected confidentiality and
ciphertext-integrity goals. The construction is Encrypt-then-MAC, so
integrity is checked before any plaintext is released by the one-shot
API. The streaming opener releases tentative plaintext into the caller's
buffer, but marks it valid only when `finish` returns `Some(())`.

### 4.4 PRF and XOF

A family `F_k` is a pseudorandom function if no efficient adversary can
distinguish `F_k` from a random function with a non-negligible advantage.
An extendable-output function is treated as a random oracle producing
arbitrarily many bytes. The instantiation is BLAKE3; the documentation
does not claim that BLAKE3 has been proven secure.

## 5. Probability and correctness notation

For a random variable `X`, `E[X]` is its expectation and `Var[X]` its
variance. `sigma` denotes a standard deviation. A working correctness
margin is written as

```text
margin = threshold / sigma,
```

with the threshold stated explicitly. A margin is a heuristic summary,
not a failure bound.

`Q(x)` is the Gaussian tail probability
`Pr[Z > x]` for a standard normal `Z`. Any use of `Q` in this
documentation is explicitly labelled a working estimate.

## 6. Protocol and oracle notation

- `A` is the Module-LWE public matrix.
- `s, e` are the long-term secret and error vectors.
- `r, e1, e2` are per-encapsulation randomness.
- `m` is the 32-byte FO message. In the public API, the `encaps` argument
  named `coins` is exactly this `m`; it is both the embedded message and
  the input to the FO randomness generator. It must be fresh and
  uniformly random for every encapsulation.
- `H(pk)` is the 32-byte unkeyed hash of the public key used in the KEM
  shared-secret derivation.
- `fake` is the 32-byte implicit-rejection seed embedded in `sk`.
- `ADRS` is the 32-byte DS address structure.
- `pubseed` is the 32-byte public DS hash key.
- `esk` is the 32-byte master DS secret; `prf` is a derived DS secret.
- `R` is the 32-byte DS randomizer.
- `md` is the 64-byte DS message digest.

## 7. Evidence notation

In [testplan.md](testplan.md) and [metrics.md](metrics.md):

| Term | Meaning |
|---|---|
| `n` | Number of timed samples or test trials, as stated. |
| `pm` | Per-mille ratio: `1000` means identical. |
| `\|t\|` | Absolute Welch t-statistic; a smoke signal, not a leakage proof. |
| `E0`–`E4` | Evidence levels defined in the test plan. |
| "recorded" | Produced by the command shown, on the machine shown, and archived locally. |
| "not reproduced in this pass" | Prior local evidence retained for context, not re-run during the documentation change. |

## 8. Normative precedence

If this document conflicts with a crate's Rust documentation, the code
and frozen KAT files take precedence. If a future change alters bytes,
the version map in [README.md](README.md) and the frozen files must be
updated together; silently changing a wire format is a specification
violation.
