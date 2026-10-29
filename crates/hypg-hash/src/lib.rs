//! `hypg-hash`: hash / XOF / keyed-hash / KDF front (`HypG` hashing pillar).
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`.
//!
//! Hardened research profile v2.0, unaudited — do not deploy. See
//! `docs/threat-model.md`.
//!
//! Thin ergonomic API over the oracle-validated portable BLAKE3 in
//! `hypg-core::b3` — no new cryptography. Every function here is a
//! documented wrapper around a core primitive that carries official
//! test vectors; this crate pins the *API contract* (digest widths,
//! streaming equivalence, domain separation) while `hypg-core` pins the
//! *primitive correctness*. See `docs/spec-hash.md`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use hypg_core::b3::{b3_derive_key, b3_expand, b3_hash, b3_kdf, b3_keyed, b3_xof};

/// 32-byte digest width (`hash32`, `keyed32`, `derive32`).
pub const DIGEST32_LEN: usize = 32;
/// 64-byte digest width (`hash64`, XOF prefix).
pub const DIGEST64_LEN: usize = 64;
/// Keyed-hash / derivation key width.
pub const KEY_LEN: usize = 32;

/// Streaming hasher re-export (chunk state + fixed CV stack, no
/// allocation). `finalize32` and `finalize_xof` agree with the one-shot
/// functions below on every input (tested).
pub use hypg_core::b3::Hasher;

/// Hash arbitrary input → 32 bytes (BLAKE3).
///
/// # Example
///
/// ```rust
/// use hypg_hash::hash32;
///
/// let mut out = [0u8; 32];
/// hash32(b"abc", &mut out);
/// assert_eq!(
///     out,
///     [
///         0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a,
///         0x8d, 0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c,
///         0xd5, 0xbd, 0x9d, 0x85,
///     ]
/// );
/// ```
pub fn hash32(input: &[u8], out: &mut [u8; DIGEST32_LEN]) {
    b3_hash(input, out);
}

/// Hash arbitrary input → 64 bytes (first 64 bytes of the BLAKE3 XOF).
/// The first 32 bytes always equal [`hash32`] of the same input
/// (BLAKE3 root-bytes property, pinned by `hash64_prefix_property`).
///
/// # Example
///
/// ```rust
/// use hypg_hash::{hash32, hash64};
///
/// let mut h32 = [0u8; 32];
/// let mut h64 = [0u8; 64];
/// hash32(b"abc", &mut h32);
/// hash64(b"abc", &mut h64);
/// assert_eq!(&h64[..32], &h32[..]);
/// ```
pub fn hash64(input: &[u8], out: &mut [u8; DIGEST64_LEN]) {
    b3_xof(out, input);
}

/// Keyed hash → 32 bytes (BLAKE3 keyed mode; MAC key as words).
/// Never equals unkeyed [`hash32`] on the same input (tested).
///
/// # Example
///
/// ```rust
/// use hypg_hash::{hash32, keyed32};
///
/// let key = [0x42u8; 32];
/// let mut mac = [0u8; 32];
/// let mut plain = [0u8; 32];
/// keyed32(&key, b"abc", &mut mac);
/// hash32(b"abc", &mut plain);
/// assert_ne!(mac, plain);
/// ```
pub fn keyed32(key: &[u8; KEY_LEN], input: &[u8], out: &mut [u8; DIGEST32_LEN]) {
    b3_keyed(key, input, out);
}

/// Key derivation: `derive_key(context, key_material)` (BLAKE3 reference
/// `derive_key` construction: context root feeds the material root).
/// Different contexts give unrelated outputs (tested).
pub fn derive32(context: &str, key_material: &[u8; KEY_LEN], out: &mut [u8; DIGEST32_LEN]) {
    b3_derive_key(context, key_material, out);
}

/// Variable-length expansion: `XOF(seed || domain)` (public lengths).
pub fn expand(out: &mut [u8], seed: &[u8; KEY_LEN], domain: &[u8]) {
    b3_expand(out, seed, domain);
}

/// Variable-length KDF: `XOF(domain || parts...)` (public lengths).
pub fn kdf(out: &mut [u8], parts: &[&[u8]], domain: &[u8]) {
    b3_kdf(out, parts, domain);
}

/// Length sanity (public, testable).
#[must_use]
pub const fn sizes_ok() -> bool {
    DIGEST32_LEN == 32 && DIGEST64_LEN == 64 && KEY_LEN == 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_hold() {
        assert!(sizes_ok());
    }

    #[test]
    fn hash32_empty_oracle() {
        // Official BLAKE3 vector: empty input.
        let mut out = [0u8; DIGEST32_LEN];
        hash32(b"", &mut out);
        assert_eq!(
            out,
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62,
            ]
        );
    }

    #[test]
    fn hash32_abc_oracle() {
        // Official BLAKE3 vector for "abc" (same anchor as the KAT file,
        // cross-checked against third-party bindings — not just our impl).
        let mut out = [0u8; DIGEST32_LEN];
        hash32(b"abc", &mut out);
        assert_eq!(
            out,
            [
                0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a,
                0x8d, 0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c,
                0xd5, 0xbd, 0x9d, 0x85,
            ]
        );
    }

    #[test]
    fn hash64_prefix_property() {
        // BLAKE3 root bytes: `hash64[..32] == hash32` on every input,
        // incl. empty, chunk-edge (1024), and multi-chunk (1025, 3000) inputs.
        let lens: [usize; 5] = [0, 1, 1024, 1025, 3000];
        for len in lens {
            let mut input = [0u8; 3000];
            let mut i = 0usize;
            while i < len {
                input[i] = u8::try_from(i.wrapping_mul(0x1F).wrapping_add(7)).unwrap_or(0);
                i += 1;
            }
            let mut h32 = [0u8; DIGEST32_LEN];
            let mut h64 = [0u8; DIGEST64_LEN];
            hash32(&input[..len], &mut h32);
            hash64(&input[..len], &mut h64);
            assert_eq!(&h64[..DIGEST32_LEN], &h32[..], "prefix mismatch at len {len}");
        }
    }

    #[test]
    fn hash64_determinism_and_sensitivity() {
        let mut a = [0u8; DIGEST64_LEN];
        let mut b = [0u8; DIGEST64_LEN];
        hash64(b"same", &mut a);
        hash64(b"same", &mut b);
        assert_eq!(a, b);
        let mut c = [0u8; DIGEST64_LEN];
        hash64(b"same!", &mut c);
        assert_ne!(a, c);
    }

    #[test]
    fn streaming_matches_oneshot_64() {
        // `Hasher` chunked updates agree with one-shot `hash64`
        // (streaming/`finalize_xof` contract at the API level).
        let mut input = [0u8; 3000];
        let mut i = 0usize;
        while i < 3000 {
            input[i] = u8::try_from(i.wrapping_mul(0x3B).wrapping_add(1)).unwrap_or(0);
            i += 1;
        }
        let mut one = [0u8; DIGEST64_LEN];
        hash64(&input, &mut one);
        for split in [0usize, 1, 1023, 1024, 2049] {
            let mut h = Hasher::new();
            h.update(&input[..split]);
            h.update(&input[split..]);
            let mut two = [0u8; DIGEST64_LEN];
            h.finalize_xof(&mut two);
            assert_eq!(one, two, "streaming mismatch at split {split}");
        }
    }

    #[test]
    fn keyed_separation() {
        let mut mac = [0u8; DIGEST32_LEN];
        let mut plain = [0u8; DIGEST32_LEN];
        keyed32(&[0x42u8; KEY_LEN], b"abc", &mut mac);
        hash32(b"abc", &mut plain);
        assert_ne!(mac, plain, "keyed must differ from unkeyed");
        let mut mac2 = [0u8; DIGEST32_LEN];
        keyed32(&[0x43u8; KEY_LEN], b"abc", &mut mac2);
        assert_ne!(mac, mac2, "different keys must differ");
        let mut mac3 = [0u8; DIGEST32_LEN];
        keyed32(&[0x42u8; KEY_LEN], b"abc", &mut mac3);
        assert_eq!(mac, mac3);
    }

    #[test]
    fn derive_context_separation() {
        let mut a = [0u8; DIGEST32_LEN];
        let mut b = [0u8; DIGEST32_LEN];
        derive32("HYP-G/test-a", &[0x42u8; KEY_LEN], &mut a);
        derive32("HYP-G/test-b", &[0x42u8; KEY_LEN], &mut b);
        assert_ne!(a, b);
        let mut a2 = [0u8; DIGEST32_LEN];
        derive32("HYP-G/test-a", &[0x42u8; KEY_LEN], &mut a2);
        assert_eq!(a, a2);
    }

    #[test]
    fn expand_kdf_shapes() {
        // Variable lengths incl. 64 (callers: per-chunk keys, domain tags).
        for len in [0usize, 1, 32, 64, 100] {
            let mut a = [0u8; 100];
            let mut b = [0u8; 100];
            expand(&mut a[..len], &[0x42u8; KEY_LEN], b"shape");
            expand(&mut b[..len], &[0x42u8; KEY_LEN], b"shape");
            assert_eq!(&a[..len], &b[..len]);
            let mut k = [0u8; 100];
            kdf(&mut k[..len], &[b"part"], b"shape");
            assert_eq!(k[..len].len(), len);
        }
    }
}
