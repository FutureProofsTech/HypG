//! `hypg-aead`: streaming AEAD front (`HypG` AEAD pillar).
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`.
//!
//! Hardened research profile v2.0, unaudited — do not deploy. See
//! `docs/threat-model.md`.
//!
//! Incremental Encrypt-then-MAC over `ChaCha20` + keyed-`BLAKE3` for
//! multi-chunk messages without full buffering (`O(1)` extra memory).
//! The wire format is **byte-identical** to one-shot `hypg-symm`
//! `seal`/`open` for the same `(key, nonce, ad, message)`: same subkeys,
//! same MAC input order (`nonce ‖ ad ‖ ct ‖ le64 lengths`), same
//! `ChaCha` counter sequence — only the *schedule* differs (incremental
//! vs one-shot). Equivalence is tested across adversarial chunkings,
//! so the existing symm KATs cover this wire format; no new frozen
//! vectors are needed. See `docs/spec-aead.md`.
//!
//! Tentative-plaintext rule (`EtM` consequence): the opener releases
//! decrypted bytes into the caller's buffer incrementally, but they
//! are **valid only after `finish` returns `Some`** — on `None` the
//! assembled buffer is zeroized. Never act on plaintext before `finish`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;

use hypg_core::b3::{b3_derive_key, Hasher};
use hypg_core::chacha::block;
use hypg_core::ct::{ct_eq, zeroize};

pub use hypg_symm::{Key, Nonce, TAG_LEN};

// Subkey domains shared with `hypg-symm` (duplicated literals, not a
// second definition: the stream/`seal` equivalence tests fail if these
// ever diverge, which is the consistency proof).
const D_ENC: &str = "HYP-G/v07/symm-enc";
const D_MAC: &str = "HYP-G/v07/symm-mac";

/// Blocks per `update` accounting: `ChaCha` consumes whole 64 B blocks.
const BLOCK_BYTES: usize = 64;

/// Buffered keystream: a partial block carries across `update` calls so
/// arbitrary (non-block-aligned) chunkings use the exact same keystream
/// bytes as one shot. `off == 64` means the buffer is empty; `next` is
/// the next fresh counter (never wraps — exhaustion fails closed).
struct Keystream {
    block: [u8; BLOCK_BYTES],
    off: usize,
    next: u64,
}

impl Keystream {
    const fn empty() -> Self {
        Self { block: [0u8; BLOCK_BYTES], off: BLOCK_BYTES, next: 0 }
    }

    /// XOR `buf` with the keystream, buffering partial blocks.
    /// `None` (leaving `buf` partially processed — callers zeroize)
    /// once the 32-bit block space is exhausted.
    fn xor(&mut self, enc: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8]) -> Option<()> {
        let mut o = 0usize;
        // Drain any buffered partial block first.
        if self.off < BLOCK_BYTES {
            let k = (BLOCK_BYTES - self.off).min(buf.len());
            let mut i = 0usize;
            while i < k {
                buf[i] ^= self.block[self.off + i];
                i += 1;
            }
            self.off += k;
            o = k;
        }
        while o < buf.len() {
            let ctr = next_counter(self.next)?;
            block(enc, nonce, ctr, &mut self.block);
            self.next = self.next.wrapping_add(1);
            let k = (buf.len() - o).min(BLOCK_BYTES);
            let mut i = 0usize;
            while i < k {
                buf[o + i] ^= self.block[i];
                i += 1;
            }
            self.off = k;
            o += k;
        }
        Some(())
    }
}

/// Streaming encryptor: `new` → `update*` → `finish` (consuming).
/// Output `(ct, tag)` equals one-shot `seal` for the concatenated input.
///
/// # Example
///
/// ```rust
/// use hypg_aead::{Key, Nonce, StreamOpener, StreamSealer, TAG_LEN};
///
/// let key = Key([0x42u8; 32]);
/// let nonce = Nonce([0x11u8; 12]);
/// let pt = b"streaming authenticated encryption";
/// let mut sealer = StreamSealer::new(&key, &nonce, b"ad");
/// let mut ct = [0u8; 34];
/// assert!(sealer.update(&pt[..5], &mut ct[..5]).is_some());
/// assert!(sealer.update(&pt[5..], &mut ct[5..]).is_some());
/// let mut tag = [0u8; TAG_LEN];
/// assert!(sealer.finish(&mut tag).is_some());
/// let mut opener = StreamOpener::new(&key, &nonce, b"ad");
/// let mut back = [0u8; 34];
/// assert!(opener.update(&ct, &mut back).is_some());
/// assert!(opener.finish(&tag, &mut back).is_some());
/// assert_eq!(&back, pt);
/// ```
pub struct StreamSealer {
    enc: [u8; 32],
    nonce: [u8; 12],
    hasher: Hasher,
    ks: Keystream,
    ad_len: u64,
    ct_len: u64,
    failed: bool,
}

/// Streaming decryptor: `new` → `update*` (tentative plaintext) →
/// `finish` (validates; zeroizes on failure). See the crate-level
/// tentative-plaintext rule.
///
/// # Example
///
/// ```rust
/// use hypg_aead::{Key, Nonce, StreamOpener, StreamSealer, TAG_LEN};
///
/// let key = Key([0x42u8; 32]);
/// let nonce = Nonce([0x11u8; 12]);
/// let mut sealer = StreamSealer::new(&key, &nonce, b"");
/// let mut ct = [0u8; 3];
/// assert!(sealer.update(b"msg", &mut ct).is_some());
/// let mut tag = [0u8; TAG_LEN];
/// assert!(sealer.finish(&mut tag).is_some());
/// // Forgery fails closed and wipes the tentative buffer.
/// ct[1] ^= 0x01;
/// let mut opener = StreamOpener::new(&key, &nonce, b"");
/// let mut back = [0xAAu8; 3];
/// assert!(opener.update(&ct, &mut back).is_some());
/// assert!(opener.finish(&tag, &mut back).is_none());
/// assert_eq!(back, [0u8; 3]);
/// ```
pub struct StreamOpener {
    enc: [u8; 32],
    nonce: [u8; 12],
    hasher: Hasher,
    ks: Keystream,
    ad_len: u64,
    ct_len: u64,
    failed: bool,
}

impl fmt::Debug for StreamSealer {
    // Redacted: key material, nonce, MAC state, and buffered keystream
    // never render.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamSealer")
            .field("ct_len", &self.ct_len)
            .field("keystream_next", &self.ks.next)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Drop for StreamSealer {
    fn drop(&mut self) {
        // Best-effort: key material, nonce copy, buffered keystream, and
        // the keyed MAC state (`Hasher` zeroizes its own fields on drop).
        zeroize(&mut self.enc);
        zeroize(&mut self.nonce);
        zeroize(&mut self.ks.block);
    }
}

impl fmt::Debug for StreamOpener {
    // Redacted: key material, nonce, MAC state, and buffered keystream
    // never render.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamOpener")
            .field("ct_len", &self.ct_len)
            .field("keystream_next", &self.ks.next)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Drop for StreamOpener {
    fn drop(&mut self) {
        zeroize(&mut self.enc);
        zeroize(&mut self.nonce);
        zeroize(&mut self.ks.block);
    }
}

/// Derive `(enc, mac)` subkeys exactly as `hypg-symm` does.
fn subkeys(key: &Key) -> ([u8; 32], [u8; 32]) {
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    b3_derive_key(D_ENC, &key.0, &mut enc);
    b3_derive_key(D_MAC, &key.0, &mut mac);
    (enc, mac)
}

/// Next counter or `None` once the 32-bit block space is exhausted.
/// Never wraps: exhaustion fails closed instead of reusing keystream.
fn next_counter(next: u64) -> Option<u32> {
    if next > u64::from(u32::MAX) {
        return None;
    }
    u32::try_from(next).ok()
}

impl StreamSealer {
    /// Begin a stream: feeds `nonce ‖ ad` into the running MAC.
    /// `ad` must be complete here (streaming `ad` is not supported —
    /// associated data is small by policy; see `spec-aead.md`).
    #[must_use]
    pub fn new(key: &Key, nonce: &Nonce, ad: &[u8]) -> Self {
        let (enc, mut mac) = subkeys(key);
        let mut hasher = Hasher::new_keyed(&mac);
        hasher.update(&nonce.0);
        hasher.update(ad);
        // The `Hasher` holds its own key-word copy and wipes it on drop;
        // wipe this local copy immediately anyway.
        zeroize(&mut mac);
        Self {
            enc,
            nonce: nonce.0,
            hasher,
            ks: Keystream::empty(),
            ad_len: ad.len() as u64,
            ct_len: 0,
            failed: false,
        }
    }

    /// Encrypt one chunk: `ct.len() == pt.len()` required. Keystream
    /// continues mid-block across chunks (buffered partial block), the
    /// counter advances, and `ct` feeds the running MAC. `None`
    /// (poisoning the stream) on length mismatch or block-space
    /// exhaustion; the output chunk is zeroized then.
    pub fn update(&mut self, pt: &[u8], ct: &mut [u8]) -> Option<()> {
        if self.failed || ct.len() != pt.len() {
            self.failed = true;
            zeroize(ct);
            return None;
        }
        let mut i = 0usize;
        while i < pt.len() {
            ct[i] = pt[i];
            i += 1;
        }
        if self.ks.xor(&self.enc, &self.nonce, ct).is_none() {
            self.failed = true;
            zeroize(ct);
            return None;
        }
        if let Some(v) = self.ct_len.checked_add(ct.len() as u64) {
            self.ct_len = v;
        } else {
            self.failed = true;
            zeroize(ct);
            return None;
        }
        self.hasher.update(ct);
        Some(())
    }

    /// Finish: feeds `le64` lengths and finalizes the tag. `None` if any
    /// `update` failed (poisoned stream).
    pub fn finish(mut self, tag: &mut [u8; TAG_LEN]) -> Option<()> {
        if self.failed {
            zeroize(tag);
            return None;
        }
        self.hasher.update(&self.ad_len.to_le_bytes());
        self.hasher.update(&self.ct_len.to_le_bytes());
        *tag = self.hasher.finalize32();
        Some(())
    }
}

impl StreamOpener {
    /// Begin a stream: feeds `nonce ‖ ad` into the running MAC.
    /// Plaintext released by `update` is tentative until `finish`.
    #[must_use]
    pub fn new(key: &Key, nonce: &Nonce, ad: &[u8]) -> Self {
        let (enc, mut mac) = subkeys(key);
        let mut hasher = Hasher::new_keyed(&mac);
        hasher.update(&nonce.0);
        hasher.update(ad);
        zeroize(&mut mac);
        Self {
            enc,
            nonce: nonce.0,
            hasher,
            ks: Keystream::empty(),
            ad_len: ad.len() as u64,
            ct_len: 0,
            failed: false,
        }
    }

    /// Decrypt one chunk tentatively: `pt.len() == ct.len()` required.
    /// Keystream continues mid-block across chunks; `ct` feeds the
    /// running MAC. `None` (poisoning the stream) on length mismatch or
    /// block-space exhaustion; `pt` zeroized then.
    pub fn update(&mut self, ct: &[u8], pt: &mut [u8]) -> Option<()> {
        if self.failed || pt.len() != ct.len() {
            self.failed = true;
            zeroize(pt);
            return None;
        }
        let mut i = 0usize;
        while i < ct.len() {
            pt[i] = ct[i];
            i += 1;
        }
        if self.ks.xor(&self.enc, &self.nonce, pt).is_none() {
            self.failed = true;
            zeroize(pt);
            return None;
        }
        if let Some(v) = self.ct_len.checked_add(ct.len() as u64) {
            self.ct_len = v;
        } else {
            self.failed = true;
            zeroize(pt);
            return None;
        }
        self.hasher.update(ct);
        Some(())
    }

    /// Finish: `pt` is the full assembled plaintext (`pt.len()` must
    /// equal the streamed `ct` length). Verifies the tag with a
    /// full-scan `ct_eq`; on mismatch zeroizes `pt` and returns `None`.
    pub fn finish(mut self, tag: &[u8; TAG_LEN], pt: &mut [u8]) -> Option<()> {
        if self.failed {
            zeroize(pt);
            return None;
        }
        if u64::try_from(pt.len()).unwrap_or(u64::MAX) != self.ct_len {
            zeroize(pt);
            return None;
        }
        self.hasher.update(&self.ad_len.to_le_bytes());
        self.hasher.update(&self.ct_len.to_le_bytes());
        let expect = self.hasher.finalize32();
        // `ct_eq` returns 1/0 branchlessly after a full scan; this `if`
        // is on its public-geometry output (both tags fully scanned).
        if ct_eq(&expect, tag) != 1 {
            zeroize(pt);
            return None;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypg_symm::{open, seal};

    const MSG_LEN: usize = 4096;

    fn key() -> Key {
        Key([0x42u8; 32])
    }
    fn nonce() -> Nonce {
        Nonce([0x11u8; 12])
    }
    fn msg() -> [u8; MSG_LEN] {
        let mut m = [0u8; MSG_LEN];
        let mut i = 0u32;
        while (i as usize) < MSG_LEN {
            m[i as usize] = u8::try_from(i.wrapping_mul(0x1F).wrapping_add(7)).unwrap_or(0);
            i += 1;
        }
        m
    }

    /// Seal `pt` through `splits` chunk boundaries (offsets into `pt`).
    fn seal_chunked(pt: &[u8], ad: &[u8], splits: &[usize]) -> ([u8; MSG_LEN], [u8; TAG_LEN]) {
        let mut sealer = StreamSealer::new(&key(), &nonce(), ad);
        let mut ct = [0u8; MSG_LEN];
        let mut prev = 0usize;
        let mut s = 0usize;
        while s < splits.len() {
            let at = splits[s];
            assert!(sealer.update(&pt[prev..at], &mut ct[prev..at]).is_some());
            prev = at;
            s += 1;
        }
        assert!(sealer.update(&pt[prev..], &mut ct[prev..]).is_some());
        let mut tag = [0u8; TAG_LEN];
        assert!(sealer.finish(&mut tag).is_some());
        (ct, tag)
    }

    #[test]
    fn stream_matches_oneshot_across_chunkings() {
        // Same bytes for whole, odd splits, 1-byte head, empty chunks.
        let pt = msg();
        let mut ct1 = [0u8; MSG_LEN];
        let mut tag1 = [0u8; TAG_LEN];
        assert!(seal(&key(), &nonce(), b"ad", &pt, &mut ct1, &mut tag1).is_some());
        let chunkings: [&[usize]; 5] =
            [&[], &[1], &[63, 64, 65, 1000], &[0, 0, 4096, 4096], &[7, 777, 2048, 3000]];
        for splits in chunkings {
            let (ct, tag) = seal_chunked(&pt, b"ad", splits);
            assert_eq!((ct, tag), (ct1, tag1), "chunking {splits:?} diverged");
        }
    }

    #[test]
    fn open_chunked_matches_oneshot() {
        let pt = msg();
        let (ct, tag) = seal_chunked(&pt, b"ad", &[100, 2000]);
        // Open through different chunk boundaries (incl. empty chunks).
        for splits in [&[][..], &[1][..], &[0, 4096][..], &[511, 512, 513][..]] {
            let mut opener = StreamOpener::new(&key(), &nonce(), b"ad");
            let mut back = [0u8; MSG_LEN];
            let mut prev = 0usize;
            let mut s = 0usize;
            while s < splits.len() {
                let at = splits[s];
                assert!(opener.update(&ct[prev..at], &mut back[prev..at]).is_some());
                prev = at;
                s += 1;
            }
            assert!(opener.update(&ct[prev..], &mut back[prev..]).is_some());
            assert!(opener.finish(&tag, &mut back).is_some());
            assert_eq!(back, pt, "chunking {splits:?} diverged");
        }
    }

    #[test]
    fn tamper_anywhere_fails_and_zeroes() {
        let pt = msg();
        let (ct, tag) = seal_chunked(&pt, b"ad", &[1024, 2048]);
        // Flip one byte per chunk region (head/mid/tail/tag).
        for pos in [0usize, 1023, 1024, 2500, 4095] {
            let mut bad = ct;
            bad[pos] ^= 0x01;
            let mut opener = StreamOpener::new(&key(), &nonce(), b"ad");
            let mut back = [0xAAu8; MSG_LEN];
            assert!(opener.update(&bad[..2048], &mut back[..2048]).is_some());
            assert!(opener.update(&bad[2048..], &mut back[2048..]).is_some());
            assert!(opener.finish(&tag, &mut back).is_none(), "forgery at {pos}");
            assert_eq!(back, [0u8; MSG_LEN], "failed finish must zero pt");
        }
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        let mut opener = StreamOpener::new(&key(), &nonce(), b"ad");
        let mut back = [0u8; MSG_LEN];
        assert!(opener.update(&ct, &mut back).is_some());
        assert!(opener.finish(&bad_tag, &mut back).is_none());
        assert_eq!(back, [0u8; MSG_LEN]);
    }

    #[test]
    fn truncate_swap_duplicate_reject() {
        let pt = msg();
        let (ct, tag) = seal_chunked(&pt, b"ad", &[1365, 2730]);
        // Truncate: drop the last chunk (tag covers full length).
        let mut opener = StreamOpener::new(&key(), &nonce(), b"ad");
        let mut back = [0u8; 2730];
        assert!(opener.update(&ct[..1365], &mut back[..1365]).is_some());
        assert!(opener.update(&ct[1365..2730], &mut back[1365..2730]).is_some());
        assert!(opener.finish(&tag, &mut back).is_none());
        // Swap: exchange chunk order (same total length, different stream).
        let mut swapped = [0u8; MSG_LEN];
        swapped[..2731].copy_from_slice(&ct[1365..]);
        swapped[2731..].copy_from_slice(&ct[..1365]);
        let mut opener = StreamOpener::new(&key(), &nonce(), b"ad");
        let mut back = [0u8; MSG_LEN];
        assert!(opener.update(&swapped, &mut back).is_some());
        assert!(opener.finish(&tag, &mut back).is_none());
        // Duplicate: replay the first chunk over the second.
        let mut dup = ct;
        dup[1365..2730].copy_from_slice(&ct[..1365]);
        let mut opener = StreamOpener::new(&key(), &nonce(), b"ad");
        let mut back = [0u8; MSG_LEN];
        assert!(opener.update(&dup, &mut back).is_some());
        assert!(opener.finish(&tag, &mut back).is_none());
    }

    #[test]
    fn wrong_params_and_poison_reject() {
        let pt = msg();
        let (ct, tag) = seal_chunked(&pt, b"ad", &[2048]);
        // Wrong ad/key/nonce at open.
        for (k, n, a) in [
            (Key([0x43u8; 32]), nonce(), b"ad".as_slice()),
            (key(), Nonce([0x12u8; 12]), b"ad".as_slice()),
            (key(), nonce(), b"ax".as_slice()),
        ] {
            let mut opener = StreamOpener::new(&k, &n, a);
            let mut back = [0u8; MSG_LEN];
            assert!(opener.update(&ct, &mut back).is_some());
            assert!(opener.finish(&tag, &mut back).is_none());
            assert_eq!(back, [0u8; MSG_LEN]);
        }
        // Length-mismatched update poisons the stream permanently.
        let mut sealer = StreamSealer::new(&key(), &nonce(), b"ad");
        let mut out = [0u8; 10];
        assert!(sealer.update(&pt[..20], &mut out).is_none());
        let mut tag = [0xAAu8; TAG_LEN];
        assert!(sealer.finish(&mut tag).is_none(), "poisoned sealer must not finish");
        assert_eq!(tag, [0u8; TAG_LEN], "poisoned finish must clear tag");
        let mut opener = StreamOpener::new(&key(), &nonce(), b"ad");
        let mut back = [0u8; 10];
        assert!(opener.update(&ct[..20], &mut back).is_none());
        assert!(opener.finish(&tag, &mut back).is_none());
    }

    #[test]
    fn empty_message_and_determinism() {
        // No updates: equals one-shot empty seal.
        let sealer = StreamSealer::new(&key(), &nonce(), b"");
        let mut tag = [0u8; TAG_LEN];
        assert!(sealer.finish(&mut tag).is_some());
        let mut ct = [0u8; 0];
        let mut tag1 = [0u8; TAG_LEN];
        assert!(seal(&key(), &nonce(), b"", b"", &mut ct, &mut tag1).is_some());
        assert_eq!(tag, tag1);
        let opener = StreamOpener::new(&key(), &nonce(), b"");
        let mut pt = [0u8; 0];
        assert!(opener.finish(&tag, &mut pt).is_some());
        // Same chunking twice: identical bytes.
        let pt = msg();
        let (c1, t1) = seal_chunked(&pt, b"ad", &[333, 2222]);
        let (c2, t2) = seal_chunked(&pt, b"ad", &[333, 2222]);
        assert_eq!((c1, t1), (c2, t2));
        // One-shot open accepts stream output (format identity).
        let mut back = [0u8; MSG_LEN];
        assert!(open(&key(), &nonce(), b"ad", &c1, &t1, &mut back).is_some());
        assert_eq!(back, pt);
    }
}
