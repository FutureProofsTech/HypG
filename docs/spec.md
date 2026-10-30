# HypG KEM normative specification (v2.0)

**Status:** normative description of the implemented KEM, revision
**2.0.0**. Research prototype; unaudited; not production-ready. The
lattice hardness of these parameters is **unconfirmed**. This document
does not assert IND-CCA2 security; it states the intended construction
and the gaps in the argument.

**Normative sources:** `crates/hypg-core/src/{params,poly,caprf,step,
state,rule,fold,ct,b3,chacha}.rs` and `crates/hypg-kem/src/lib.rs`.
Frozen vectors: `crates/hypg-kat/kats/v2.0.0.txt`.

## 1. Scope and naming

The profile is referred to as `HypG-KEM-1024` in prose. The frozen KAT
header string is

```text
hypg_version = 2.0.0-module-n256-k4-q4096-b3
```

This is a Module-LWE KEM over the ring

```text
R_q = Z_q[X]/(X^256 + 1),   q = 4096 = 2^12,
```

with module rank `k = 4`, centered-binomial secrets and errors of
parameter `eta = 2`, and a 32-byte message encoded one bit per
coefficient. The public key is 1568 bytes, the ciphertext is 1440 bytes,
the secret key is 1632 bytes, and the shared secret is 32 bytes.

The construction is an FO-style transform with implicit rejection. It is
not byte-compatible with ML-KEM, not an implementation of FIPS 203, and
not covered by an external security proof or estimator result. See
[nist-alignment.md](nist-alignment.md).

## 2. Primitive and encoding conventions

### 2.1 Hash functions

Let `H(x)` be unkeyed BLAKE3-256, `H_k(x)` keyed BLAKE3-256 with a
32-byte key `k`, and `XOF(x,L)` the first `L` bytes of the BLAKE3 XOF on
`x`. The core API also provides

```text
b3_expand(out, seed, domain) = XOF(seed || domain, len(out)),
b3_kdf(out, parts, domain)   = XOF(domain || parts[0] || parts[1] || ..., len(out)).
```

`b3_kdf` has no length-prefix framing. Every caller in this
specification uses either fixed-length parts or a single variable-length
part with an unambiguous domain. A new caller must check this property
before using `b3_kdf`.

### 2.2 CA-PRF

For a 32-byte `seed`, public domain byte string `d`, and output length
`L`, define:

```text
init    = XOF(seed || d || "-init", 256)
rule    = XOF(seed || d, 64)
state_0 = LE^{-1}(init)                  # 32 little-endian u64 words
state_32 = CA^32(state_0; rule)
out     = XOF(d || LE(state_32) || d || "-out", L)
```

`LE(state_32)` is the 256-byte little-endian serialization of the 32
state words. `CA^32` applies the following round 32 times, with a fresh
temporary array each round; after all 32 words of a round are computed,
the temporary array replaces the state.

For round index `t` in `[0,32)` and word index `i` in `[0,32)`:

```text
rc  = 0x9E3779B97F4A7C15 + (t+1)*0xBF58476D1CE4E5B9   (mod 2^64)
a   = S[i]
b   = S[(i+1)  mod 32]
c   = S[(i+5)  mod 32]
d   = S[(i+17) mod 32]
rk  = R[i mod 8] XOR rc XOR (i * 0xBF58476D1CE4E5B9)
t1  = a XOR ROTL(b,13) XOR ROTL(c,7)
t2  = (t1 AND d) XOR ((NOT t1) AND b)
t3  = t2 + (rk XOR (i + t))                    (mod 2^64)
t4  = t3 XOR ROTL(t3,29)
t5  = (t4 * 0xD6E8FEB86659FD93) XOR ROTL(d,11)
S'[i] = t5 XOR ROTL(S[(i+16) mod 32],17) XOR rc
```

All arithmetic is modulo `2^64`; rotations are 64-bit left rotations.
The rule `R` is eight 64-bit words decoded little-endian from `rule`.
The CA is a deterministic mixing stage. The final BLAKE3 XOF is the
security-relevant expander; see [design.md](design.md#5-the-ca-prf-expander).

The `ca_expand` implementation copies at most 59 bytes of `d` before
`"-init"` and at most 60 bytes before `"-out"`. Every protocol domain in
[domains.md](domains.md) is shorter than these limits, so truncation
never occurs in this specification.

### 2.3 Polynomials and vectors

A polynomial is a 256-coefficient array in `[0,q)`. The following
operations are normative.

- `Add(a,b)`: `(a_i + b_i) mod q`.
- `Sub(a,b)`: `(a_i - b_i) mod q`.
- `Mul(a,b)`: negacyclic convolution modulo `X^256 + 1`, computed with
  an integer accumulator and reduced modulo `q`.
- `Dot(a,b)`: sum of `Mul(a_i,b_i)` over the common length. On unequal
  lengths the implementation consumes the common prefix; protocol calls
  always use length 4.

`CBD2(B)` takes 128 bytes and returns a polynomial:

```text
for i in [0,256):
    (b0,b1,b2,b3) = successive bits of B starting at bit 4*i
    v = b0 + b1 - b2 - b3
    out[i] = (v + q) mod q
```

The bit order is least-significant bit first within each byte.

`Encode(m)` maps 32 bytes to a polynomial by

```text
out[i] = bit_i(m) * 2048,   bit_i(m) = (m[i/8] >> (i mod 8)) & 1.
```

`Decode(v)` is

```text
bit_i = ((((v_i + 1024) mod q) >> 11) & 1),
```

with the output bits packed least-significant first within each byte.
This is rounding to the nearest of `{0, 2048}` with wrap-around.

`Compress10(c) = ((c + 2) >> 2) mod 2^10`; decompression is
`Compress10(c) << 2`. `Compress5(c) = ((c + 64) >> 7) mod 2^5`;
decompression is `Compress5(c) << 7`. Packing is the little-endian
bitstream specified in [parameters.md](parameters.md#24-integer-and-packing-details).

## 3. Key generation

`KeyGen(seed)` is deterministic. `seed` is a 32-byte caller-supplied
value with at least 256 bits of entropy.

```text
KeyGen(seed):
  seed_a = CA-PRF(seed, "HYP-G/v07/seed-a", 32)
  A      = ParseMatrix(CA-PRF(seed_a, "HYP-G/v07/poly-a", 6144))
  s      = ParseCBDVector(CA-PRF(seed, "HYP-G/v07/sec-s", 512))
  e      = ParseCBDVector(CA-PRF(seed, "HYP-G/v07/sec-e", 512))

  for i in [0,4):
      b[i] = Dot(A[i], s) + e[i]          # in R_q

  pk = seed_a || pack12(b[0]) || pack12(b[1])
                || pack12(b[2]) || pack12(b[3])

  fake = CA-PRF(seed, "HYP-G/v07/fake", 32)
  sk   = seed || fake || pk

  return (pk, sk)
```

`ParseMatrix` reads the 6144-byte expander output in row-major order:
entry `(i,j)` is the 384-byte block at offset `(4*i+j)*384`, unpacked as
12-bit coefficients. `ParseCBDVector` reads four consecutive 128-byte
blocks and applies `CBD2` to each.

All intermediate `s`, `e`, `fake`, and `sk` buffers are best-effort
zeroized before return, except the returned `sk` bytes. The
returned `SecretKey` is not `Copy`, has a redacted `Debug`, compares in
constant time, and best-effort zeroizes on drop.

## 4. Encapsulation

`Encaps(pk, coins)` is deterministic. **The 32-byte `coins` argument is
the FO message `m` itself.** It is embedded in `c2` and is also the input
to the randomness generator. It must be freshly generated by a CSPRNG for
every encapsulation. Reusing `(pk, coins)` repeats the same ciphertext
and shared secret; using low-entropy `coins` weakens the scheme.

```text
Encaps(pk, m):
  (seed_a, b) = ParsePK(pk)
  A           = ParseMatrix(CA-PRF(seed_a, "HYP-G/v07/poly-a", 6144))
  rseed       = H(m || pk || "HYP-G/v07/r-seed")

  r  = ParseCBDVector(CA-PRF(rseed, "HYP-G/v07/rand-r",  512))
  e1 = ParseCBDVector(CA-PRF(rseed, "HYP-G/v07/rand-e1", 512))
  e2 = CBD2(CA-PRF(rseed, "HYP-G/v07/rand-e2", 128)[0:128])

  for i in [0,4):
      c1[i] = Dot(Column_i(A), r) + e1[i]     # A^T r + e1
  c2 = Dot(b, r) + e2 + Encode(m)

  ct = pack10(Compress10(c1[0])) || ... || pack10(Compress10(c1[3]))
       || pack5(Compress5(c2))

  pk_hash = H(pk)
  ss      = XOF("HYP-G/v07/ss" || m || ct || pk_hash, 32)

  return (ct, ss)
```

`Column_i(A)` is the vector `(A[0][i], A[1][i], A[2][i], A[3][i])`;
the implementation multiplies by the transpose directly. The `rseed`
hash input is exactly 32 bytes of `m`, 1568 bytes of `pk`, and the
16-byte ASCII suffix `"HYP-G/v07/r-seed"`, with no separators beyond
the fixed field lengths and the distinct suffix.

The public key parser does not validate that `pk` was produced by
`KeyGen`. Any 1568-byte string is accepted and unpacked into 12-bit
coefficients. Encapsulation is total for all such strings, but a
malformed `pk` has no security guarantee.

## 5. Decapsulation

```text
Decaps(sk, ct):
  (seed, fake, pk) = ParseSK(sk)
  (seed_a, b)      = ParsePK(pk)
  A                = ParseMatrix(CA-PRF(seed_a, "HYP-G/v07/poly-a", 6144))
  s                = ParseCBDVector(CA-PRF(seed, "HYP-G/v07/sec-s", 512))

  (c1, c2) = UnpackAndDecompress(ct)
  v        = c2 - Dot(s, c1)
  m'       = Decode(v)

  rseed'   = H(m' || pk || "HYP-G/v07/r-seed")
  r',e1',e2' = Expand(rseed')
  ct'      = Reencrypt(A, b, m', r', e1', e2')
  ok       = ct_eq(ct', ct)                 # 1 if equal, 0 otherwise

  pk_hash  = H(pk)
  ss_ok    = XOF("HYP-G/v07/ss" || m' || ct || pk_hash, 32)
  ss_rej   = XOF("HYP-G/v07/reject" || fake || ct, 32)

  ss = ct_select(ok, ss_ok, ss_rej)
  return ss
```

The implementation always computes `m'`, the re-encryption, both shared
secrets, and the select. `ct_eq` scans the full 1440-byte ciphertext and
returns 0 or 1 without an early exit. `ct_select` produces
`ss_ok` when `ok = 1` and `ss_rej` when `ok = 0` using a byte mask.

`Decaps` never returns an error. A malformed or forged ciphertext yields
a value derived from the secret `fake` value and the presented
ciphertext. This is implicit rejection. It does **not** mean the caller
can safely ignore authentication: protocols must arrange that the peer
detects a mismatched shared secret, for example by authenticating a
subsequent message.

## 6. Correctness

### 6.1 Noise without compression

**Lemma 1 (noise identity).** For a ciphertext produced by `Encaps` and
then unpacked by `Decaps`, before compression effects are considered,

```text
c2 - <s,c1> = Encode(m) + <e,r> + e2 - <s,e1>.
```

*Proof.* Expand `b = A*s + e` and `c1 = A^T*r + e1`, then use the
associativity and commutativity of multiplication in `R_q`. The terms
`<A*s,r>` and `<s,A^T*r>` are equal because they are the same sum over
the same index pairs. ∎

Write the PKE decryption value as

```text
v = c2 - <s,c1>
  = <b,r> + e2 + Encode(m) - <s, A^T r + e1>
  = <A*s + e, r> + e2 - <s,A^T r> - <s,e1> + Encode(m)
  = Encode(m) + <e,r> + e2 - <s,e1>.
```

The noise is therefore

```text
N_0 = <e,r> + e2 - <s,e1>.
```

Each coefficient of `<e,r>` is a sum of `k*256 = 1024` products of
independent `CBD(2)` coefficients. Each product has variance `1`, so
this term has variance `1024`. The term `-<s,e1>` has the same variance.
The `e2` coefficient has variance `1`. Under the working independence
model, `Var[N_0] = 2049` and `sigma(N_0) = 45.3`.

### 6.2 Compression residuals

Decompression introduces small residuals:

```text
c1' = c1 + Delta1,   Delta1 in {-1,0,1,2} per coefficient,
c2' = c2 + Delta2,   Delta2 in {-63,...,64} per coefficient,
```

where the values are taken modulo `q` and interpreted in the signed
small range. Therefore

```text
v' = Encode(m) + N_0 + Delta2 - <s,Delta1>.
```

Over uniformly distributed coefficients, `Delta1` has mean `1/2` and
variance `1.25`; `Delta2` has mean `1/2` and variance `1365.25`. A
working variance model gives

| Component | Variance |
|---|---:|
| `<e,r>` | 1024 |
| `-<s,e1>` | 1024 |
| `e2` | 1 |
| `-<s,Delta1>` | 1280 |
| `Delta2` | 1365.25 |
| total | 4694.25 |
| standard deviation | 68.5 |

Rounding up, the working model is `sigma ~= 70`. The message decision
boundary is half the encoding spacing, `2048/2 = 1024`, giving a working
margin of

```text
1024 / 70 ~= 14.6 sigma.
```

This is a heuristic estimate, not a formal failure bound. The
independence and Gaussian approximations are not proven; the residuals
are bounded and their distribution is not exactly normal. A formal
analysis should bound the tail of the bounded-sum distribution directly
and should not rely on the Gaussian figure.

The in-tree failure test uses 32 trials. It is a regression tripwire, not
evidence for a `2^-128` failure rate. A defensible correctness argument
requires an analytic tail bound plus a much larger empirical sample
(at least `10^6` trials, with the exact sample size and confidence
interval documented). That work is **not completed**.

### 6.3 Re-encryption equality

**Lemma 2 (deterministic re-encryption).** If `Decode(v') = m`, then
`ct' = ct` and `Decaps` selects `ss_ok`.

*Proof.* `m' = m` makes `rseed'`, `(r',e1',e2')`, the PKE ciphertext,
and the packed ciphertext identical to the encapsulation values because
every expansion, compression, and packing step is deterministic. The
fixed-length packing is injective on its input format. The equality
check therefore returns 1. ∎

If no coefficient decodes incorrectly, `m' = m`. The re-encryption then
recomputes the same `rseed`, the same `(r,e1,e2)`, the same PKE
ciphertext, and the same packing. Thus `ct' = ct`, `ok = 1`, and
`ss = ss_ok`. If any coefficient decodes incorrectly, the re-encryption
check fails with overwhelming probability under the hash and LWE
assumptions; the exact probability of a re-encryption collision is part
of the unproven FO analysis.

## 7. Intended security argument and its gaps

The intended argument has four steps.

1. **PKE confidentiality.** Under Module-LWE, `(A, A*s+e, A^T*r+e1,
   <b,r>+e2+Encode(m))` hides `m` for a passive adversary.
2. **FO conversion.** The re-encryption check makes a modified ciphertext
   decrypt to a different message or fail the check; the random-oracle
   derivation of `(r,e1,e2)` from `(m,pk)` prevents an adversary from
   choosing consistent randomness.
3. **Implicit rejection.** Invalid ciphertexts map to a secret-key-bound
   pseudorandom value, avoiding a public validity oracle.
4. **Domain separation.** The `seed-a`, `sec-s`, `sec-e`, `poly-a`,
   `rand-r`, `rand-e1`, `rand-e2`, `fake`, `r-seed`, `ss`, and `reject`
   domains are distinct ASCII strings and are used with fixed input
   layouts.

The gaps are material:

- No cited theorem covers the exact shared-secret derivation
  `KDF(m || ct || H(pk))` and rejection derivation
  `KDF(fake || ct)`. The construction is FO-style, not a verbatim
  standardized FO variant. A proof must be adapted and checked.
- The `CA-PRF` stage is not an additional proven hardness assumption.
  The final BLAKE3 XOF is the security-relevant expander; the CA is a
  design hedge.
- The Module-LWE parameters `(n=256, k=4, q=4096, eta=2)` have not been
  run through the community lattice estimator. The power-of-two modulus
  differs from ML-KEM-1024's `3329`, so ML-KEM numbers do not transfer.
- No external cryptanalysis, no machine-checked proof, and no formal
  verification exist.
- The decapsulation failure probability has not been bounded to the
  standard required for a CCA reduction.

Consequently, the KEM is **not claimed IND-CCA2 secure**. The intended
target is IND-CCA2 at a security level consistent with the parameter
profile, contingent on the missing analysis.

## 8. Wire format and input validation

The byte layouts are normative and are repeated in
[parameters.md](parameters.md#23-wire-layout). Length checks are public
and happen before indexing. The implementation's `sizes_ok` predicate is

```text
PK_LEN == SEED_LEN + B_PACKED_LEN
CT_LEN == C1_VEC_PACKED_LEN + C2_PACKED_LEN.
```

`PublicKey::from_bytes` and `Ciphertext::from_bytes` are infallible
wrappers around the fixed-size arrays. They do not validate algebraic
structure. `SecretKey::from_bytes` similarly accepts arbitrary bytes;
callers should only construct keys with `keygen` and should treat parsed
keys as untrusted until checked at the protocol level.

Malformed but correctly sized inputs cannot cause an out-of-bounds
access in safe Rust. The decapsulation path is total: unequal-length
`dot` calls consume the common prefix, and the fixed-size unpackers
consume exactly their arrays.

## 9. Determinism and reproducibility

`KeyGen` is a pure function of `seed`. `Encaps` is a pure function of
`(pk, coins)`. `Decaps` is a pure function of `(sk, ct)`. There is no
internal RNG, clock, allocator, or global state in `hypg-kem`.

This determinism is useful for KATs and cross-architecture comparison,
but it imposes caller duties:

- `seed` must be a CSPRNG output, never a counter or password.
- `coins` must be a fresh 32-byte CSPRNG output per encapsulation.
- Reusing `coins` with the same `pk` repeats the ciphertext and secret.
- Reusing `coins` with a different `pk` is still unsafe as a general
  randomness-reuse pattern; do not do it.

## 10. Frozen vectors and checksum

The KEM KAT file contains three tags (`0x00`, `0x42`, `0xFF`), each with
a deterministic `seed`, `pk`, `sk`, `ct`, and `ss`, plus a BLAKE3
`"abc"` anchor. The file is 28,514 bytes.

```text
SHA-256(crates/hypg-kat/kats/v2.0.0.txt)
= 3b2dde3d1138c11b54a6880f50ca7b4390071ae53aa94601075f39b2af971d4b
```

The file is compared byte-for-byte by
`cargo test -p hypg-kat --lib`. A cross-architecture run produced
identical 234,114 bytes on x86-64 and `qemu-aarch64` for the complete
four-file KAT set; see [testplan.md](testplan.md).

## 11. Explicit limitations

The KEM specification is not a security certification. In particular:

- no lattice-estimator result or bit-security claim;
- no proof for the exact FO variant;
- no analytic decapsulation-failure bound;
- no external audit or formal verification;
- no `dudect`-grade constant-time evaluation;
- no power, electromagnetic, or fault-injection results;
- no claim of NIST compliance or FIPS validation;
- no production deployment approval.

See [threat-model.md](threat-model.md) and
[deployment.md](deployment.md) before considering any use outside a
research environment.
