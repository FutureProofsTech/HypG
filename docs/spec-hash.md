# HypG hash, XOF, and KDF specification (v2.0)

**Status:** normative description of the implemented hash API, revision
**2.0.0**. Research prototype; unaudited. The cryptographic primitive is
portable BLAKE3; this crate is an API contract, not a new hash function.

**Normative sources:** `crates/hypg-hash/src/lib.rs` and
`crates/hypg-core/src/b3.rs`. Frozen vectors:
`crates/hypg-kat/kats-hash/v2.0.0.txt`.

## 1. Scope

`hypg-hash` exposes the BLAKE3 family used by the rest of HypG:

| Function | Semantics | Output |
|---|---|---:|
| `hash32(input, out)` | Unkeyed BLAKE3 hash. | 32 bytes |
| `hash64(input, out)` | First 64 bytes of the BLAKE3 XOF. | 64 bytes |
| `keyed32(key, input, out)` | Keyed BLAKE3 with a 32-byte key. | 32 bytes |
| `derive32(context, material, out)` | BLAKE3 `derive_key`. | 32 bytes |
| `expand(out, seed, domain)` | `XOF(seed \|\| domain)`. | `out.len()` |
| `kdf(out, parts, domain)` | `XOF(domain \|\| parts...)`. | `out.len()` |
| `Hasher` | Streaming BLAKE3 with `finalize32` / `finalize_xof`. | 32 or arbitrary |

No function in this crate implements a custom round function, a custom
mode of operation, or a new compression function. The underlying BLAKE3
implementation is in `hypg-core::b3`.

## 2. BLAKE3 instantiation

The implementation is portable scalar BLAKE3 with the standard

- 8-word chaining value;
- 16-word message block;
- 7 rounds per compression;
- 64-byte blocks and 1024-byte chunks;
- binary Merkle tree with parent nodes;
- 32-byte keyed-hash key;
- 32-byte XOF root and 64-byte output blocks.

The IV and message permutation are the BLAKE3 reference constants. The
implementation uses the standard flags for chunk start, chunk end,
parent, root, keyed hash, derive-key context, and derive-key material.
It is not a reduced-round or parameterized variant.

The streaming `Hasher` uses a fixed 54-level chaining-value stack. This
supports the full 64-bit BLAKE3 input-length space without allocation.
It stores the key, chaining value, current block, chunk counter, and
stack in a struct whose `Debug` is redacted and whose `Drop` zeroizes
the keyed material.

## 3. API semantics

### 3.1 `hash32`

```rust
pub fn hash32(input: &[u8], out: &mut [u8; 32]);
```

This is unkeyed BLAKE3-256. It is the standard hash used for public
values such as `H(pk)` and the KEM randomness seed. It is not a MAC.

### 3.2 `hash64`

```rust
pub fn hash64(input: &[u8], out: &mut [u8; 64]);
```

This returns the first 64 bytes of the BLAKE3 XOF. BLAKE3 has the
root-bytes property: the first 32 bytes equal `hash32(input)` for every
input. The test suite pins this for empty, short, chunk-edge (1024),
and multi-chunk (1025, 3000) inputs.

`hash64` is not a separate 512-bit hash with an independent IV. Callers
that need domain-separated 64-byte outputs should use `expand` with a
domain rather than assuming a different hash.

### 3.3 `keyed32`

```rust
pub fn keyed32(key: &[u8; 32], input: &[u8], out: &mut [u8; 32]);
```

This is BLAKE3 keyed mode. The key is exactly 32 bytes. It is used for
the AEAD MAC and the DS tweakable hash. A keyed output is distinct from
the unkeyed hash of the same input; the tests check this and check key
separation.

Keyed BLAKE3 is a PRF/MAC construction, but no formal proof for the
implementation exists. The security argument treats it as a secure PRF.

### 3.4 `derive32`

```rust
pub fn derive32(context: &str, key_material: &[u8; 32], out: &mut [u8; 32]);
```

This is the BLAKE3 `derive_key` construction. The context string is
processed under the derive-key-context flags; its root becomes the key
for the key-material root. Distinct contexts produce unrelated outputs.
The context is a UTF-8 string, not an arbitrary byte string.

This function is used for the AEAD subkeys and the Symm KAT anchor. It
is not used as a general KDF for variable-length outputs; use `kdf` for
that.

### 3.5 `expand`

```rust
pub fn expand(out: &mut [u8], seed: &[u8; 32], domain: &[u8]);
```

This computes

```text
XOF(seed || domain, len(out)).
```

It has no length prefix between `seed` and `domain`. `seed` is fixed at
32 bytes, and every protocol caller uses a compile-time public domain,
so the concatenation is unambiguous. A new caller must ensure that no
two different `(seed, domain)` pairs can produce the same byte string;
a domain that can contain attacker-controlled bytes needs an explicit
length framing.

`expand` is the primitive behind `CA-PRF`'s init, rule, and outer stages,
and the `b3_expand` helper. It is not itself the CA-PRF.

### 3.6 `kdf`

```rust
pub fn kdf(out: &mut [u8], parts: &[&[u8]], domain: &[u8]);
```

This computes

```text
XOF(domain || parts[0] || parts[1] || ..., len(out)).
```

There is no separator or length prefix between parts. The KEM and CA-PRF
callers use fixed-length parts or a single part with a distinct domain.
A new caller must ensure that the part sequence is injective; for
variable-length parts, add explicit lengths or use `derive32`.

### 3.7 Streaming `Hasher`

```rust
let mut h = Hasher::new();          // unkeyed
h.update(b"part one");
h.update(b"part two");
let digest = h.finalize32();

let mut h = Hasher::new_keyed(&key); // keyed
h.update(input);
let mut out = [0u8; 96];
h.finalize_xof(&mut out);
```

`update` may be called with arbitrary chunk boundaries. `finalize32`
returns the 32-byte root; `finalize_xof` returns the requested prefix of
the XOF. `finalize32` and the first 32 bytes of `finalize_xof` agree.

`Hasher` is `Clone`. Cloning duplicates keyed state; callers should treat
the clone as secret material and drop it promptly. The original and the
clone are independent after cloning.

## 4. Domain separation and composition

The hash API is deliberately small. Protocol domain separation lives in
the callers:

- KEM domains are ASCII constants under `HYP-G/v07/`.
- DS uses keyed BLAKE3 with `pubseed` and explicit PRF/F tags.
- AEAD uses `derive_key` contexts for subkeys and a fully specified MAC
  input.
- The CA-PRF uses `"-init"` and `"-out"` suffixes and a final XOF domain.

None of these calls relies on a hidden prefix in the hash function. If a
caller concatenates variable-length fields with `expand` or `kdf`
without lengths, that caller is responsible for the injectivity of the
encoding.

## 5. Test vectors and validation

The hash KAT file records:

- `hash32` and `hash64` for empty, `"abc"`, and a 1025-byte pattern;
- a `keyed32` anchor with a 32-byte `0x42` key on `"abc"`;
- a `derive32` anchor with context `"HYP-G/v07/kat"` and a 32-byte
  `0x42` key material.

The file is 923 bytes.

```text
SHA-256(crates/hypg-kat/kats-hash/v2.0.0.txt)
= 5fa778035ce2e8aa9c89345458ba4da67df4bdbe71a456cbb58026cf9341d9f1
```

The implementation is also pinned against official BLAKE3 vectors for
empty input and `"abc"` in unit tests, and against vectors captured from
the official `blake3` crate (`v1.8.7`) for the portable scalar path. The
repository does not include the complete official BLAKE3 test-vector
corpus, and the implementation has not been independently validated as a
BLAKE3 library. It should not be used as a general-purpose BLAKE3
replacement outside HypG.

## 6. Security position

The intended assumptions are:

- BLAKE3 is collision-resistant and preimage-resistant at 256 bits;
- keyed BLAKE3 is a secure PRF/MAC with a 256-bit key;
- the BLAKE3 XOF is a random oracle for the output lengths used here.

No proof of these assumptions is included. BLAKE3 is a relatively young
primitive compared with SHA-2/SHA-3, and the portable implementation is
scalar and unoptimized. The implementation avoids `unsafe`, but safe Rust
does not imply constant-time machine code. Keyed hashing and CA state
handling have not been measured against cache-timing or power analysis.

## 7. Explicit limitations

The hash API is not:

- a FIPS-approved hash or MAC (BLAKE3 is not approved for FIPS 140
  modules);
- a password-hashing function;
- a key-stretching function;
- a general-purpose KDF without caller-supplied framing;
- a side-channel-hardened implementation;
- an audited or formally verified BLAKE3 implementation.

Use it as the primitive layer of the research profile, not as a
standalone production hash service.
