# Domain-separation registry

**Status:** normative registry for every domain string, tag byte, and
structured hash input in the active 2.0.0 / DS 2.0.1 wire formats.
Domains are public; they are not keys.

## 1. Conventions

- Domain strings are ASCII byte strings, case-sensitive, with no
  terminating NUL.
- `CA-PRF(seed, d, L)` uses the domain `d` in three places:
  `d || "-init"`, `d` alone for the rule, and `d || "-out"`.
- `b3_expand(out, seed, d) = XOF(seed || d, len(out))`.
- `b3_kdf(out, parts, d) = XOF(d || parts..., len(out))`.
- Keyed BLAKE3 uses a 32-byte key and does not append a length.
- Unless otherwise noted, all concatenations are exact and have fixed
  field lengths.

## 2. KEM domains

All KEM strings are under the historical `HYP-G/v07/` prefix.

| Domain | Input construction | Output use |
|---|---|---|
| `HYP-G/v07/seed-a` | `CA-PRF(seed, d, 32)` | `seed_a` |
| `HYP-G/v07/sec-s` | `CA-PRF(seed, d, 512)` | four 128-byte CBD inputs for `s` |
| `HYP-G/v07/sec-e` | `CA-PRF(seed, d, 512)` | four 128-byte CBD inputs for `e` |
| `HYP-G/v07/poly-a` | `CA-PRF(seed_a, d, 6144)` | `4×4` matrix of packed 12-bit polynomials |
| `HYP-G/v07/rand-r` | `CA-PRF(rseed, d, 512)` | four 128-byte CBD inputs for `r` |
| `HYP-G/v07/rand-e1` | `CA-PRF(rseed, d, 512)` | four 128-byte CBD inputs for `e1` |
| `HYP-G/v07/rand-e2` | `CA-PRF(rseed, d, 128)` | one 128-byte CBD input for `e2` |
| `HYP-G/v07/fake` | `CA-PRF(seed, d, 32)` | implicit-rejection key |
| `HYP-G/v07/r-seed` | `BLAKE3(m \|\| pk \|\| d)` | 32-byte FO randomness seed |
| `HYP-G/v07/ss` | `XOF(d \|\| m \|\| ct \|\| H(pk), 32)` | accepted shared secret |
| `HYP-G/v07/reject` | `XOF(d \|\| fake \|\| ct, 32)` | rejected shared secret |

The KEM `r-seed` input has fixed lengths: `m` is 32 bytes, `pk` is
1568 bytes, and the suffix is 16 bytes. The `ss` input has fixed
lengths: `m` is 32, `ct` is 1440, and `H(pk)` is 32. The reject input
has `fake` 32 and `ct` 1440. No length prefixes are needed because the
layouts are fixed by the protocol.

`CA-PRF` in the KEM uses the exact construction in
[spec.md](spec.md#2-primitive-and-encoding-conventions). The CA stage is
shared across all these domains; the outer BLAKE3 XOF domain is the
same `d`.

## 3. Symm and AEAD domains

| Context | Input | Output |
|---|---|---|
| `HYP-G/v07/symm-enc` | `DK(context, master_key)` | ChaCha20 encryption key |
| `HYP-G/v07/symm-mac` | `DK(context, master_key)` | keyed-BLAKE3 MAC key |

The AEAD MAC input is not a `b3_kdf` domain string; it is a structured
input:

```text
nonce(12) || ad || ct || LE64(len(ad)) || LE64(len(ct)).
```

The MAC key is the `symm-mac` subkey. The nonce is included in the MAC
even though it is also the ChaCha nonce. This binds the ciphertext to
the nonce and prevents cross-nonce tag reuse.

There is no separate domain byte in the tag input. Domain separation
comes from the two `derive_key` contexts and the fixed MAC layout.

## 4. DS domains and tags

### 4.1 String domains

| Domain | Input construction | Output use |
|---|---|---|
| `HYP-G/v07/ds-addrnd` | `CA-PRF(prf, d, 64)` | randomizer stream |
| `HYP-G/v07/ds-msghash` | appended in `Digest` | message-digest separation |
| `HYP-G/v07/ds-pubseed` | `CA-PRF(esk, d, 32)` | public hash key |
| `HYP-G/v07/ds-prf` | `CA-PRF(esk, d, 32)` | randomizer seed |

`R` is

```text
BLAKE3(CA-PRF(prf, "HYP-G/v07/ds-addrnd", 64) || BLAKE3(msg)).
```

`md` uses the `ds-msghash` bytes as a suffix:

```text
md[c] = BLAKE3(R || pubseed || root || BLAKE3(msg) || LE32(c)
               || "HYP-G/v07/ds-msghash"),
       c in {0,1}.
```

### 4.2 Tweakable-hash tags

| Function | Input | Length |
|---|---|---:|
| `PRF` | `0x01 \|\| seed(32) \|\| ADRS(32)` | 65 |
| `F` | `0x02 \|\| ADRS(32) \|\| x(32)` | 65 |
| `H` | `ADRS(32) \|\| left(32) \|\| right(32)` | 96 |

`PRF` and `F` are both keyed BLAKE3 with `pubseed`. The tags are the
v2.0.1 fix. Without them, a 64-byte `PRF` input `seed || ADRS` and a
64-byte `F` input `ADRS || x` could be byte-identical when
`seed = ADRS = x` (or more generally when the two concatenations
coincide). The tags make the first byte different in every call.

`H` is untagged. Its 96-byte input cannot collide with a 65-byte input
under a length-preserving interpretation, and its field order is fixed.
If a future revision adds a variable-length `H` input or another
96-byte tweakable call, an explicit tag must be added.

The following strings from older design drafts are **not** used:

```text
HYP-G/v07/ds-fors
HYP-G/v07/ds-wots
HYP-G/v07/ds-tree
```

DS tweak separation uses `ADRS` type and fields, not those strings.

## 5. CA-PRF suffixes

For a CA domain `d`, the implementation constructs:

```text
init_domain = d || "-init"     (at most 59 bytes of d are copied)
rule_domain = d
out_domain  = d || "-out"      (at most 60 bytes of d are copied)
```

The active domains are much shorter than the truncation limits, so the
suffix is always complete. The rule expansion does not append a suffix
and uses the same `d` as the outer final XOF. The two constructions are
distinguished by their input lengths and by the final XOF domain, which
includes both `d` and `d || "-out"`.

## 6. Collision and cross-protocol analysis

The following checks are part of the design review.

1. **KEM vs. Symm vs. DS.** The top-level prefixes differ:
   `HYP-G/v07/` is shared, but the next component is `seed-a`,
   `sec-s`, `sec-e`, `poly-a`, `rand-*`, `fake`, `r-seed`, `ss`,
   `reject`, `symm-enc`, `symm-mac`, `ds-addrnd`, `ds-msghash`,
   `ds-pubseed`, or `ds-prf`. No two protocol roles share a string.
2. **KEM fixed layouts.** Every concatenation used with `b3_kdf` has
   fixed field lengths, so concatenation is injective. The `r-seed`
   hash has fixed lengths plus a suffix.
3. **AEAD MAC.** Nonce (fixed 12), AD (variable), ciphertext (variable),
   and two fixed 8-byte lengths are concatenated in that order. The
   length suffix makes the encoding injective for all `(ad,ct)` pairs.
   An empty AD and a one-byte AD with the same ciphertext produce
   different inputs.
4. **DS PRF/F.** The explicit tags make the two 65-byte inputs
   disjoint. `H` has a different length and a different arity.
5. **FORS root compression.** The input is a fixed 32-byte address
   (type 0, field 20 all ones) followed by 35 fixed 32-byte roots. It
   is keyed BLAKE3, not `H`; it cannot collide with an `H` call under
   the fixed-length encoding.
6. **Digest domain.** The digest includes a counter and the fixed
   `ds-msghash` suffix, so the two 32-byte halves are domain-separated.

The registry does not prove that the surrounding protocol is free of
cross-protocol attacks. A caller that reuses a KEM shared secret, an AEAD
key, and a signing key across different applications can still create
cross-protocol links. Protocol-level key separation is the caller's
responsibility.

## 7. Change control

Adding a domain requires:

- a unique ASCII string that does not prefix-collide with an existing
  one;
- a fixed input layout or explicit length framing;
- a new KAT vector if the change affects output bytes;
- an update to this registry, [parameters.md](parameters.md), and the
  relevant specification;
- a version bump if the wire format changes.

Removing or renaming a domain is a breaking wire-format change. The
historical `v07` strings must not be repurposed for a new meaning; create
a new string and a new version instead.
