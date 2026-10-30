# HypG Symm one-shot AEAD specification (v2.0)

**Status:** normative description of the implemented one-shot AEAD,
revision **2.0.0**. The construction is unchanged from the project's
v0.7 Symm construction. Research prototype; unaudited; not
production-ready.

**Normative sources:** `crates/hypg-symm/src/lib.rs` and
`crates/hypg-core/src/{chacha,b3,ct}.rs`. Frozen vectors:
`crates/hypg-kat/kats-symm/v2.0.0.txt`.

## 1. Construction summary

HypG Symm is an Encrypt-then-MAC AEAD:

- **Confidentiality:** IETF ChaCha20 (RFC 8439), 32-byte key, 12-byte
  nonce, initial counter 0.
- **Integrity:** keyed BLAKE3-256 over
  `nonce || ad || ct || LE64(ad_len) || LE64(ct_len)`.
- **Key separation:** two subkeys are derived from the 32-byte master key
  with BLAKE3 `derive_key`, using distinct context strings.

The composition uses each primitive for its designed purpose. It is not
a new stream cipher or a new MAC. It is also not a standardized AEAD
algorithm, and it has no nonce-misuse resistance.

## 2. Types and parameters

```text
Key   = [u8; 32]
Nonce = [u8; 12]
Tag   = [u8; 32]
MAX_MSG_LEN = 2^38 bytes = 274,877,906,944 bytes
```

`Key` is not `Copy`; its `Debug` is redacted; equality is constant-time;
`Drop` best-effort zeroizes it. `Nonce` is public and `Copy`. `Tag` is
a fixed-size byte array. The API does not hide the nonce, because nonce
uniqueness is the caller's responsibility and the nonce is not secret.

The limit is exactly `2^32` ChaCha20 blocks of 64 bytes. Counter values
`0..=u32::MAX` are usable; a message of exactly `MAX_MSG_LEN` bytes
fits. A larger message is rejected before encryption.

## 3. Key schedule

```text
enc = DK("HYP-G/v07/symm-enc", master_key)
mac = DK("HYP-G/v07/symm-mac", master_key)
```

`DK(context, key)` is the BLAKE3 reference `derive_key` construction:
the context string is processed under the derive-key context flags, and
its root becomes the key for the material root. This is the standard
BLAKE3 key-derivation mode, not a custom hash of `context || key`.

The master key is never used directly for ChaCha20 or for the MAC. The
two context strings are distinct, so the subkeys are domain-separated.
The derived subkeys are best-effort zeroized after use.

## 4. One-shot sealing

```text
Seal(K, N, AD, M):
  if len(M) != len(C): return None
  if len(M) > MAX_MSG_LEN: return None

  (enc, mac) = KeySchedule(K)
  C = M
  if ChaCha20_XOR(enc, N, counter=0, C) != len(C): return None
  T = KeyedBLAKE3(mac, N || AD || C || LE64(len(AD)) || LE64(len(C)))
  return (C, T)
```

The API signature is

```rust
pub fn seal(
    key: &Key,
    nonce: &Nonce,
    ad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) -> Option<()>;
```

The output buffer must be exactly `pt.len()` bytes. On a length error,
the implementation zeroizes `ct` and `tag` and returns `None`. The
ChaCha20 path uses the same in-place XOR routine as the streaming API:
counter starts at 0, each 64-byte block is generated with the IETF
12-byte nonce layout, and the counter never wraps.

The tag covers the ciphertext, not the plaintext. This is the defining
property of Encrypt-then-MAC. The length suffix is included after the
ciphertext and covers both associated-data and ciphertext lengths; it is
not optional and is present even for empty inputs.

## 5. One-shot opening

```text
Open(K, N, AD, C, T):
  if len(C) != len(P): return None
  if len(C) > MAX_MSG_LEN: return None

  (enc, mac) = KeySchedule(K)
  T' = KeyedBLAKE3(mac, N || AD || C || LE64(len(AD)) || LE64(len(C)))
  if ct_eq(T', T) != 1: return None

  P = C
  if ChaCha20_XOR(enc, N, counter=0, P) != len(P): return None
  return P
```

The API signature is

```rust
pub fn open(
    key: &Key,
    nonce: &Nonce,
    ad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    pt: &mut [u8],
) -> Option<()>;
```

`open` verifies the tag **before** writing any decrypted byte. On a tag
mismatch or a length error, `pt` is left untouched. On a ChaCha counter
failure (which cannot occur for an accepted length), `pt` is zeroized
and `None` is returned.

The caller must treat `None` as an authentication failure, not as an
empty plaintext. The function does not return partial plaintext.

## 6. Wire format

The wire object is the pair `(ct, tag)`. There is no header, version
byte, or length field. Protocol framing must carry:

- the message length (or a delimiter);
- the associated data;
- the nonce;
- the tag.

The cryptographic binding is to the full ciphertext and both lengths,
but the wire format itself does not encode the nonce or associated data.
A protocol that loses either binding loses the security property that
the tag is intended to provide.

## 7. Correctness and determinism

For every accepted `(key, nonce, ad, message)`:

```text
Open(Seal(...)) = message
```

`Seal` is deterministic in its inputs. There is no internal randomness.
The same key, nonce, AD, and message produce the same ciphertext and tag.
This is expected for a stream cipher and is why nonce uniqueness is
mandatory.

## 8. Security position

### 8.1 Intended properties

Under the assumptions that ChaCha20 is a secure stream cipher, keyed
BLAKE3 is a secure PRF/MAC, and the key schedule is domain-separated,
the EtM composition is intended to provide:

- confidentiality of the message against passive adversaries;
- integrity and authenticity of the ciphertext and associated data;
- resistance to ciphertext modification, truncation, extension, and
  reordering at the AEAD layer;
- 256-bit integrity against forgery attempts that do not break the MAC.

The 32-byte tag is the full keyed-BLAKE3 output. There is no truncation.

### 8.2 Nonce discipline

The nonce is 12 bytes. It **must be unique for every message encrypted
under a given key**. Reusing `(key, nonce)` with different messages:

- reuses the ChaCha20 keystream, which reveals the XOR of plaintexts;
- creates two ciphertexts under the same keystream, and the MAC does not
  repair the confidentiality failure.

There is no nonce-misuse-resistant mode, no synthetic IV, and no
automatic nonce generation. A caller that cannot guarantee uniqueness
must not use this AEAD.

### 8.3 Composition caveats

- No proof for this exact ChaCha20 + BLAKE3 EtM composition is included.
  The composition is standard in structure, but the primitives are not
  the ones used in ChaCha20-Poly1305 or AES-GCM.
- No key-commitment property is claimed. If a protocol needs key
  commitment, it must be added at the protocol layer.
- The AEAD is not FIPS-approved: ChaCha20 and BLAKE3 are not approved
  primitives for U.S. federal cryptographic modules.
- Associated data is authenticated but not encrypted. It must not contain
  secrets that the protocol is unwilling to expose.
- The implementation has no nonce-reuse detection, no replay protection,
  and no message-framing logic.

### 8.4 Side channels

The one-shot `seal` and `open` use fixed loop bounds based on public
lengths. The tag comparison is a full-scan constant-time equality. The
implementation has not been evaluated with `dudect`, nor with power, EM,
or fault laboratories. The code is branchless with respect to secret
bytes by construction, but compiler-generated code and microarchitectural
effects are not analysed.

## 9. Errors and buffer discipline

`seal` returns `None` for:

- `ct.len() != pt.len()`;
- `pt.len() > MAX_MSG_LEN`;
- a ChaCha counter failure (not reachable for an accepted length).

`open` returns `None` for:

- `pt.len() != ct.len()`;
- `ct.len() > MAX_MSG_LEN`;
- a tag mismatch;
- a ChaCha counter failure (not reachable for an accepted length).

On failure, `seal` zeroizes its output buffers; `open` leaves `pt`
untouched on authentication failure. Callers must check the `Option`;
there is no sentinel plaintext.

## 10. Frozen vectors and checksum

The Symm KAT file contains five cases:

| Case | Plaintext | AD | Key byte | Nonce byte |
|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | `0x42` | `0x11` |
| 1 | 1 | 1 | `0x00` | `0xFF` |
| 2 | 127 | 128 | `0xA5` | `0x5A` |
| 3 | 128 | 0 | `0xFF` | `0x00` |
| 4 | 1000 | 1000 | `0x33` | `0x77` |

Each case records `key`, `nonce`, `ct`, and `tag`. The file is 3,662
bytes.

```text
SHA-256(crates/hypg-kat/kats-symm/v2.0.0.txt)
= 91b7942ffb4a3c5da8b8b589268af7b7d1594796b428efdc7e26c567c5f04208
```

The streaming API is byte-identical to this one-shot format; see
[spec-aead.md](spec-aead.md).

## 11. Explicit limitations

This AEAD is not:

- a standardized or NIST-approved AEAD;
- nonce-misuse resistant;
- proven secure as a composition;
- side-channel or fault-injection evaluated;
- a replacement for a validated AEAD in a production system.

Use it only inside the research profile described in
[threat-model.md](threat-model.md), and only with a correct protocol
framing and nonce discipline.
