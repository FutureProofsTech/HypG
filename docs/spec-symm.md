# HypG-Symm v0.7 Normative Spec (Encrypt-then-MAC rebuild)

Status: **FROZEN for 2.0 (parameters v0.7, unchanged)**.
Platinum: `no_std`, zero dependencies, bit-exact LE.

## 0. Construction: ChaCha20 + keyed-BLAKE3 (Encrypt-then-MAC)

v0.7 retires the Keccak duplex (gone with the hash migration) and
rebuilds the AEAD from the two new primitives, each used as designed —
no novel composition:

- Encryption: IETF ChaCha20 (RFC 8439 §2), 12-byte nonce, initial
  counter 0, over the full message.
- Authentication: keyed BLAKE3 over
  `nonce ‖ ad ‖ ct ‖ le64(ad_len) ‖ le64(ct_len)` (length suffix kills
  concatenation ambiguity without padding rules).
- Keys: `(enc_key, mac_key)` derive from the 32-byte master key via
  BLAKE3 `derive_key` under `HYP-G/v07/symm-enc` / `HYP-G/v07/symm-mac`.
  The master key is never used directly.

Decrypt verifies the tag first (constant-time `ct_eq` full scan), then
decrypts; `pt` is left untouched on failure.

## 1. Parameters

| Param | Value | Notes |
|---|---|---|
| Master key | 32 B | caller-supplied, CSPRNG |
| Subkeys | 2 × 32 B | derived per operation (cheap: 2 hashes) |
| Nonce | 12 B | unique per `(key, message)` — caller duty |
| Tag | 32 B | full keyed-BLAKE3 output |
| Message limit | < 2³⁸ B (2³² blocks) | enforced (`None` beyond; public length) |
| `ct.len()` | `== pt.len()` | stream cipher, no expansion |

## 2. Algorithms

```text
seal(key, nonce, ad, pt) -> (ct, tag) or None:
  require ct.len() == pt.len() and fits_block_space(pt.len())
  (enc, mac) = subkeys(key)
  ct = pt; chacha_xor(enc, nonce, 0, ct)   # in place
  tag = keyed(mac, nonce || ad || ct || le64(|ad|) || le64(|ct|))
  zeroize(enc, mac)

open(key, nonce, ad, ct, tag) -> pt or None:
  require pt.len() == ct.len() and fits_block_space
  (enc, mac) = subkeys(key)
  expect = keyed(mac, nonce || ad || ct || le64(|ad|) || le64(|ct|))
  if ct_eq(expect, tag) != 1: zeroize(enc, mac); return None  # pt untouched
  pt = ct; chacha_xor(enc, nonce, 0, pt)
  zeroize(enc, mac)
```

## 3. Public API (Rust)

```rust
pub struct Key(pub [u8; 32]);    // + zeroize()
pub struct Nonce(pub [u8; 12]);
pub const TAG_LEN: usize = 32;
pub fn seal(key, nonce, ad, pt, ct: &mut [u8], tag: &mut [u8; 32]) -> Option<()>;
pub fn open(key, nonce, ad, ct, tag: &[u8; 32], pt: &mut [u8]) -> Option<()>;
pub use hypg_core::b3::{b3_expand, b3_hash as symm_hash, b3_kdf}; // hash/XOF access
```

Lengths are public; mismatches return `None` (no panics). Failure
leaves `pt` untouched (stronger than zeroize-then-fail: callers can
distinguish "untouched" from "erased" buffers in tests).

## 4. Security position (honest)

- Target 128-bit PQ: ChaCha20 (256-bit key, best attacks ≈ brute force)
  + 256-bit keyed-BLAKE3 tags (Grover preimage 2¹²⁸, forgery needs the
  MAC key). Nonce discipline is the caller's: reuse under one key
  destroys confidentiality (keystream repeat) but not authenticity.
- Random 12 B nonces collide at ≈ 2⁴⁸ messages (birthday); counters
  preferred past that. Rekey before ~2⁴⁸ messages regardless.
- Branchless w.r.t. secrets: fixed 64 B block stepping (public
  lengths), no secret branches/indices; tag check via `ct_eq` full scan.
- Backlog: third-party review of the EtM binding (MAC input layout)
  and the subkey derivation contexts.

## 5. Test plan (v0.7 gates)

- Unit: rate-edge sweep (63/64/65 B blocks), AD variants, tamper matrix
  (ct/tag/key/nonce/ad flips → `None`, `pt` untouched), determinism,
  subkey separation, length-mismatch `None`.
- KAT freeze `kats-symm/v2.0.0.txt` (empty, 1 B, rate/block edges,
  1000 B).
- Redteam S9 unchanged in shape (adapted nonces).
- Bench: `seal/open` throughput + forged-tag timing ratio; CLI
  `seal/open/hash` (`hash` now prints `b3_256`).
