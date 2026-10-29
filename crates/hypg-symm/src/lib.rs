//! `hypg-symm`: AEAD + hash/XOF (`HypG` symmetric pillar).
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`.
//!
//! Hardened research profile v2.0, unaudited — do not deploy. See
//! `docs/threat-model.md`.
//!
//! Encrypt-then-MAC: `ChaCha20` stream encryption plus a keyed-BLAKE3 tag
//! over `nonce ‖ ad ‖ ct ‖ le64(ad_len) ‖ le64(ct_len)`. Each primitive
//! is used as designed (no novel composition): the stream never
//! authenticates, the MAC never encrypts. Subkeys derive from the master
//! key via BLAKE3 `derive_key`. See `docs/spec-symm.md` for the normative
//! construction and the honest security position (128-bit PQ target,
//! nonce discipline is the caller's).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use hypg_core::b3::{b3_derive_key, Hasher};
use hypg_core::chacha::xor_in_place;
use hypg_core::ct::{ct_eq, zeroize};

pub use hypg_core::b3::{b3_expand, b3_hash as symm_hash, b3_kdf};

/// AEAD master key: 32 bytes (subkeys derived, never used directly).
pub const KEY_LEN: usize = 32;
/// AEAD nonce: 12 bytes (RFC 8439 style; unique per `(key, message)`).
pub const NONCE_LEN: usize = 12;
/// AEAD tag: 32 bytes (full keyed-BLAKE3 output).
pub const TAG_LEN: usize = 32;
/// Maximum message bytes per `(key, nonce)`: 2³² `ChaCha20` blocks.
pub const MAX_MSG_LEN: u64 = (0xFFFF_FFFFu64 + 1) * 64;

const D_ENC: &str = "HYP-G/v07/symm-enc";
const D_MAC: &str = "HYP-G/v07/symm-mac";

/// AEAD key with best-effort erasure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key(pub [u8; KEY_LEN]);

/// AEAD nonce (public, but must be unique per message under one key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Key {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
    /// Parse from bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }
    /// Best-effort in-place erasure (see `hypg_core::ct::zeroize`).
    pub fn zeroize(&mut self) {
        zeroize(&mut self.0);
    }
}

impl Nonce {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
    /// Parse from bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; NONCE_LEN]) -> Self {
        Self(b)
    }
}

/// Subkeys `(enc, mac)` from the master key (domain-separated).
fn subkeys(key: &Key) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut enc = [0u8; KEY_LEN];
    let mut mac = [0u8; KEY_LEN];
    b3_derive_key(D_ENC, &key.0, &mut enc);
    b3_derive_key(D_MAC, &key.0, &mut mac);
    (enc, mac)
}

/// Authentication input binding: `nonce ‖ ad ‖ ct ‖ le64 lengths`.
/// Streaming (no concatenation buffer); lengths are public.
fn mac_tag(mac_key: &[u8; KEY_LEN], nonce: &Nonce, ad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut h = Hasher::new_keyed(mac_key);
    h.update(&nonce.0);
    h.update(ad);
    h.update(ct);
    h.update(&(ad.len() as u64).to_le_bytes());
    h.update(&(ct.len() as u64).to_le_bytes());
    h.finalize32()
}

/// Message fits the 32-bit `ChaCha20` block space (public length check).
fn fits_block_space(len: usize) -> bool {
    // `len/64` blocks needed; valid counters are `0..=u32::MAX`.
    u32::try_from((len as u64) / 64).is_ok()
}

/// Encrypt + authenticate. Requires `ct.len() == pt.len()` and a message
/// inside the block space (public lengths); `None` otherwise.
///
/// # Example
///
/// ```rust
/// use hypg_symm::{open, seal, Key, Nonce, TAG_LEN};
///
/// let key = Key([0x42u8; 32]);
/// let nonce = Nonce([0x11u8; 12]);
/// let pt = b"hello hypg-symm";
/// let mut ct = [0u8; 15];
/// let mut tag = [0u8; TAG_LEN];
/// assert!(seal(&key, &nonce, b"ad", pt, &mut ct, &mut tag).is_some());
/// let mut back = [0u8; 15];
/// assert!(open(&key, &nonce, b"ad", &ct, &tag, &mut back).is_some());
/// assert_eq!(&back, pt);
/// // Forgery fails closed: `None`, plaintext buffer untouched.
/// let mut bad_tag = tag;
/// bad_tag[0] ^= 1;
/// let mut untouched = [0xFFu8; 15];
/// assert!(open(&key, &nonce, b"ad", &ct, &bad_tag, &mut untouched).is_none());
/// assert_eq!(untouched, [0xFFu8; 15]);
/// ```
pub fn seal(
    key: &Key,
    nonce: &Nonce,
    ad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) -> Option<()> {
    if ct.len() != pt.len() || !fits_block_space(pt.len()) {
        return None;
    }
    let (mut enc, mut mac) = subkeys(key);
    let mut i = 0usize;
    while i < pt.len() {
        ct[i] = pt[i];
        i += 1;
    }
    if xor_in_place(&enc, &nonce.0, 0, ct) != ct.len() {
        zeroize(ct);
        zeroize(&mut enc);
        zeroize(&mut mac);
        return None;
    }
    *tag = mac_tag(&mac, nonce, ad, ct);
    zeroize(&mut enc);
    zeroize(&mut mac);
    Some(())
}

/// Verify + decrypt. Returns `None` (leaving `pt` untouched) on tag
/// mismatch or length mismatch. Plaintext has no safe implicit value,
/// so failure is signaled — unlike KEM `ss` (see spec §4).
pub fn open(
    key: &Key,
    nonce: &Nonce,
    ad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    pt: &mut [u8],
) -> Option<()> {
    if pt.len() != ct.len() || !fits_block_space(ct.len()) {
        return None;
    }
    let (mut enc, mut mac) = subkeys(key);
    let expect = mac_tag(&mac, nonce, ad, ct);
    // `ct_eq` returns 1/0 branchlessly after a full scan; this `if` is on
    // its public-geometry output (both tags fully scanned first).
    if ct_eq(&expect, tag) != 1 {
        zeroize(&mut enc);
        zeroize(&mut mac);
        return None;
    }
    let mut i = 0usize;
    while i < ct.len() {
        pt[i] = ct[i];
        i += 1;
    }
    if xor_in_place(&enc, &nonce.0, 0, pt) != pt.len() {
        zeroize(pt);
        zeroize(&mut enc);
        zeroize(&mut mac);
        return None;
    }
    zeroize(&mut enc);
    zeroize(&mut mac);
    Some(())
}

/// Length sanity (public, testable).
#[must_use]
pub const fn sizes_ok() -> bool {
    TAG_LEN == 32 && KEY_LEN == 32 && NONCE_LEN == 12
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_hold() {
        assert!(sizes_ok());
    }
    fn key() -> Key {
        Key([0x42u8; KEY_LEN])
    }
    fn nonce() -> Nonce {
        Nonce([0x11u8; NONCE_LEN])
    }

    #[test]
    fn round_trip_sweep() {
        // Block edges (63/64/65), empty, multi-block, odd tail.
        let lens: [usize; 7] = [0, 1, 63, 64, 65, 256, 1000];
        for len in lens {
            let mut pt = [0u8; 1000];
            let mut i = 0u32;
            let want = u32::try_from(len).unwrap_or(1000);
            while i < want {
                let b = u8::try_from(i).unwrap_or(0xFF);
                pt[i as usize] = b.wrapping_mul(0x1F).wrapping_add(7);
                i += 1;
            }
            let (pt, mut ct, mut back) = (&pt[..len], [0u8; 1000], [0u8; 1000]);
            let (ct, back) = (&mut ct[..len], &mut back[..len]);
            let mut tag = [0u8; TAG_LEN];
            assert!(seal(&key(), &nonce(), b"ad", pt, ct, &mut tag).is_some());
            assert!(open(&key(), &nonce(), b"ad", ct, &tag, back).is_some());
            assert_eq!(back, pt, "round-trip failed at len {len}");
        }
    }

    #[test]
    fn ad_variants() {
        let pt = b"authenticated message";
        let ads: [&[u8]; 4] = [b"", b"a", &[0xAAu8; 128], &[0x55u8; 1000]];
        for ad in ads {
            let mut ct = [0u8; 21];
            let mut back = [0u8; 21];
            let mut tag = [0u8; TAG_LEN];
            assert!(seal(&key(), &nonce(), ad, pt, &mut ct, &mut tag).is_some());
            assert!(open(&key(), &nonce(), ad, &ct, &tag, &mut back).is_some());
            assert_eq!(&back, pt);
        }
    }

    #[test]
    fn tamper_rejects_and_leaves_pt() {
        let pt = b"secret plaintext block";
        let mut ct = [0u8; 22];
        let mut tag = [0u8; TAG_LEN];
        assert!(seal(&key(), &nonce(), b"ad", pt, &mut ct, &mut tag).is_some());
        for i in [0usize, 11, 21] {
            let mut bad = ct;
            bad[i] ^= 0x01;
            let mut back = [0xFFu8; 22];
            assert!(open(&key(), &nonce(), b"ad", &bad, &tag, &mut back).is_none());
            assert_eq!(back, [0xFFu8; 22], "failed open must not touch pt");
        }
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        let mut back = [0u8; 22];
        assert!(open(&key(), &nonce(), b"ad", &ct, &bad_tag, &mut back).is_none());
        let mut back2 = [0u8; 22];
        assert!(open(&key(), &nonce(), b"ax", &ct, &tag, &mut back2).is_none());
        let mut back3 = [0u8; 22];
        assert!(open(&Key([0x43u8; KEY_LEN]), &nonce(), b"ad", &ct, &tag, &mut back3).is_none());
        let mut back4 = [0u8; 22];
        assert!(open(&key(), &Nonce([0x12u8; NONCE_LEN]), b"ad", &ct, &tag, &mut back4).is_none());
    }

    #[test]
    fn length_mismatch_is_none() {
        let mut ct = [0u8; 10];
        let mut tag = [0u8; TAG_LEN];
        assert!(seal(&key(), &nonce(), b"", b"0123456789ABC", &mut ct, &mut tag).is_none());
        let mut pt = [0u8; 11];
        assert!(open(&key(), &nonce(), b"", &ct, &tag, &mut pt).is_none());
    }

    #[test]
    fn block_space_boundaries() {
        // Predicate-only (no 256 GiB allocation): `MAX_MSG_LEN` is
        // `2^32` blocks, so `2^38 - 1` bytes fit and `2^38` do not.
        assert!(fits_block_space(0));
        assert!(fits_block_space(63));
        assert!(fits_block_space(64));
        let max_ok = usize::try_from(MAX_MSG_LEN - 1).unwrap_or(0);
        assert!(fits_block_space(max_ok));
        let min_bad = usize::try_from(MAX_MSG_LEN).unwrap_or(usize::MAX);
        assert!(!fits_block_space(min_bad));
        assert!(!fits_block_space(usize::MAX));
    }
    #[test]
    fn nonce_reuse_documents_determinism() {
        // Same `(key, nonce)`, different messages: both decrypt, outputs
        // differ. The construction is deterministic, so nonce reuse leaks
        // message equality — pinned here, forbidden by policy.
        let (k, n) = (key(), nonce());
        let (mut c1, mut c2) = ([0u8; 16], [0u8; 16]);
        let (mut t1, mut t2) = ([0u8; TAG_LEN], [0u8; TAG_LEN]);
        assert!(seal(&k, &n, b"ad", b"message one!!!!!", &mut c1, &mut t1).is_some());
        assert!(seal(&k, &n, b"ad", b"message two!!!!!", &mut c2, &mut t2).is_some());
        assert_ne!((c1, t1), (c2, t2));
        let (mut b1, mut b2) = ([0u8; 16], [0u8; 16]);
        assert!(open(&k, &n, b"ad", &c1, &t1, &mut b1).is_some());
        assert!(open(&k, &n, b"ad", &c2, &t2, &mut b2).is_some());
        assert_eq!(b1, *b"message one!!!!!");
        assert_eq!(b2, *b"message two!!!!!");
    }

    #[test]
    fn exhaustive_single_byte_messages() {
        // All 256 one-byte plaintexts round-trip (fast ops only —
        // the small-space exhaustive complement to the sweep tests).
        let mut b = 0u32;
        while b < 256 {
            let pt = [u8::try_from(b).unwrap_or(0)];
            let mut ct = [0u8; 1];
            let mut tag = [0u8; TAG_LEN];
            assert!(seal(&key(), &nonce(), b"ad", &pt, &mut ct, &mut tag).is_some());
            let mut back = [0u8; 1];
            assert!(open(&key(), &nonce(), b"ad", &ct, &tag, &mut back).is_some());
            assert_eq!(back, pt);
            b += 1;
        }
    }

    #[test]
    fn determinism_and_nonce_sensitivity() {
        let pt = b"same message";
        let (mut c1, mut c2) = ([0u8; 12], [0u8; 12]);
        let (mut t1, mut t2) = ([0u8; TAG_LEN], [0u8; TAG_LEN]);
        assert!(seal(&key(), &nonce(), b"", pt, &mut c1, &mut t1).is_some());
        assert!(seal(&key(), &nonce(), b"", pt, &mut c2, &mut t2).is_some());
        assert_eq!((c1, t1), (c2, t2));
        let (mut c3, mut t3) = ([0u8; 12], [0u8; TAG_LEN]);
        assert!(seal(&key(), &Nonce([0x99u8; NONCE_LEN]), b"", pt, &mut c3, &mut t3).is_some());
        assert_ne!((c3, t3), (c1, t1));
    }

    #[test]
    fn key_zeroize() {
        let mut k = key();
        k.zeroize();
        assert_eq!(k.0, [0u8; KEY_LEN]);
    }

    #[test]
    fn subkeys_differ_and_bind() {
        let (e1, m1) = subkeys(&key());
        let (e2, m2) = subkeys(&Key([0x43u8; KEY_LEN]));
        assert_ne!((e1, m1), (e2, m2));
        assert_ne!(e1, m1);
    }
}
