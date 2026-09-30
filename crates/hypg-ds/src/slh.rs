//! SLH composition: `R` randomizer, message digest split, sign/verify.
//!
//! `md[64]` via BLAKE3 streaming over `R ‖ pubseed ‖ root ‖ msg-digest`
//! (arbitrary message lengths, no concatenation buffers). Digest bits:
//! FORS `30×7`, tree `60`, leaf `5` (275 bits of 512). Deterministic:
//! same `(sk, msg)` → same `sig`.

use hypg_core::b3::{b3_hash, Hasher};
use hypg_core::caprf::ca_expand;
use hypg_core::ct::zeroize;

use crate::fors::{self, ForsSig};
use crate::hypertree::{self, LayerSig};
use crate::params::{FORS_K, N, SIG_LEN, SIG_PK_LEN, SIG_SK_LEN};

const D_ADDRND: &[u8] = b"HYP-G/v07/ds-addrnd";
const D_MSGHASH: &[u8] = b"HYP-G/v07/ds-msghash";
const D_PUBSEED: &[u8] = b"HYP-G/v07/ds-pubseed";
const D_PRF: &[u8] = b"HYP-G/v07/ds-prf";

/// Public key: `root(32) || pubseed(32)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigPk(pub [u8; SIG_PK_LEN]);

/// Secret key: `esk(32) || prf(32) || pubseed(32) || root(32)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigSk(pub [u8; SIG_SK_LEN]);

impl SigPk {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIG_PK_LEN] {
        &self.0
    }
    /// Parse from bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; SIG_PK_LEN]) -> Self {
        Self(b)
    }
}

impl SigSk {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIG_SK_LEN] {
        &self.0
    }
    /// Parse from bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; SIG_SK_LEN]) -> Self {
        Self(b)
    }
    /// Best-effort in-place erasure.
    pub fn zeroize(&mut self) {
        zeroize(&mut self.0);
    }
}

fn sk_parts(sk: &[u8; SIG_SK_LEN]) -> ([u8; N], [u8; N], [u8; N], [u8; N]) {
    let mut esk = [0u8; N];
    let mut prf = [0u8; N];
    let mut pubseed = [0u8; N];
    let mut root = [0u8; N];
    let mut i = 0usize;
    while i < N {
        esk[i] = sk[i];
        prf[i] = sk[N + i];
        pubseed[i] = sk[2 * N + i];
        root[i] = sk[3 * N + i];
        i += 1;
    }
    (esk, prf, pubseed, root)
}

/// Hedged randomizer: `R = BLAKE3(ca_stream(prf) || BLAKE3(msg))`
/// (deterministic in `(sk, msg)`; streaming binds arbitrary lengths).
fn randomizer(prf_seed: &[u8; N], msg: &[u8]) -> [u8; N] {
    let mut stream = [0u8; 64];
    ca_expand(&mut stream, prf_seed, D_ADDRND);
    let mut mhash = [0u8; N];
    b3_hash(msg, &mut mhash);
    let mut h = Hasher::new();
    h.update(&stream);
    h.update(&mhash);
    h.finalize32()
}

/// Message digest `md[64]`: binds `R`, `pubseed`, `root`, `msg`.
#[allow(clippy::many_single_char_names)]
fn digest(r: &[u8; N], pubseed: &[u8; N], root: &[u8; N], msg: &[u8]) -> [u8; 64] {
    let mut mhash = [0u8; N];
    b3_hash(msg, &mut mhash);
    let mut md = [0u8; 64];
    let mut ctr = 0u32;
    while ctr < 2 {
        // r ‖ pubseed ‖ root ‖ mhash ‖ le32(ctr) ‖ domain (streamed).
        let mut h = Hasher::new();
        h.update(r);
        h.update(pubseed);
        h.update(root);
        h.update(&mhash);
        h.update(&ctr.to_le_bytes());
        h.update(D_MSGHASH);
        let out = h.finalize32();
        let mut i = 0usize;
        while i < N {
            md[ctr as usize * N + i] = out[i];
            i += 1;
        }
        ctr += 1;
    }
    md
}

/// Bit `pos` of `md` (public index).
fn md_bit(md: &[u8; 64], pos: usize) -> u32 {
    u32::from((md[pos / 8] >> (pos % 8)) & 1)
}

/// Split digest: 30 FORS indices (7 bits), 60-bit tree index, 5-bit leaf.
fn split(md: &[u8; 64]) -> ([u32; FORS_K], u64, u32) {
    let mut fors = [0u32; FORS_K];
    let mut t = 0usize;
    while t < FORS_K {
        let mut v = 0u32;
        let mut b = 0usize;
        while b < 7 {
            v |= md_bit(md, t * 7 + b) << b;
            b += 1;
        }
        fors[t] = v;
        t += 1;
    }
    let mut tree_idx = 0u64;
    let mut b = 0usize;
    while b < 60 {
        tree_idx |= u64::from(md_bit(md, 210 + b)) << b;
        b += 1;
    }
    let mut leaf = 0u32;
    b = 0;
    while b < 5 {
        leaf |= md_bit(md, 270 + b) << b;
        b += 1;
    }
    (fors, tree_idx, leaf)
}

/// Generate `(pk, sk)` deterministically from a 32-byte `esk`.
#[must_use]
pub fn ds_keygen(esk: &[u8; N]) -> (SigPk, SigSk) {
    let mut pubseed = [0u8; N];
    ca_expand(&mut pubseed, esk, D_PUBSEED);
    let root = hypertree::ht_root(&pubseed, esk);
    let mut pk = [0u8; SIG_PK_LEN];
    let mut sk = [0u8; SIG_SK_LEN];
    let mut i = 0usize;
    while i < N {
        pk[i] = root[i];
        pk[N + i] = pubseed[i];
        sk[i] = esk[i];
        sk[3 * N + i] = root[i];
        i += 1;
    }
    // `prf` and `pubseed` slots.
    let mut prf = [0u8; N];
    ca_expand(&mut prf, esk, D_PRF);
    i = 0;
    while i < N {
        sk[N + i] = prf[i];
        sk[2 * N + i] = pubseed[i];
        i += 1;
    }
    (SigPk(pk), SigSk(sk))
}

/// Signing prelude: hedged randomizer, digest split, and the secret key
/// material a signer needs. Pure function of `(sk, msg)`; the returned
/// components feed independent parallel units in threaded signers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreSign {
    /// Hedged randomizer `R`.
    pub r: [u8; N],
    /// Master secret seed.
    pub esk: [u8; N],
    /// Public seed.
    pub pubseed: [u8; N],
    /// FORS leaf indices (30 × 7 bits).
    pub fors_idx: [u32; FORS_K],
    /// Hypertree selector (60 bits).
    pub tree_idx: u64,
    /// Bottom-layer leaf index (5 bits).
    pub leaf: u32,
}

/// Compute [`PreSign`] (fast: two hashes + splits, no trees).
#[must_use]
pub fn pre_sign(sk: &SigSk, msg: &[u8]) -> PreSign {
    let (esk, prf_seed, pubseed, root) = sk_parts(&sk.0);
    let r = randomizer(&prf_seed, msg);
    let md = digest(&r, &pubseed, &root, msg);
    let (fors_idx, tree_idx, leaf) = split(&md);
    PreSign { r, esk, pubseed, fors_idx, tree_idx, leaf }
}

/// Serialize `R ‖ FORS ×30 ‖ layers ×12` into the exact `SIG_LEN` buffer.
/// Shared by serial and threaded signers (single serialization truth).
#[allow(clippy::many_single_char_names)]
pub fn serialize_sig(
    r: &[u8; N],
    fors_sig: &ForsSig,
    ht_sig: &[LayerSig; 12],
    sig_out: &mut [u8; SIG_LEN],
) {
    let mut o = 0usize;
    let mut i = 0usize;
    while i < N {
        sig_out[o] = r[i];
        o += 1;
        i += 1;
    }
    let mut t = 0usize;
    while t < FORS_K {
        i = 0;
        while i < N {
            sig_out[o] = fors_sig[t].0[i];
            o += 1;
            i += 1;
        }
        let mut h = 0usize;
        while h < 7 {
            i = 0;
            while i < N {
                sig_out[o] = fors_sig[t].1[h][i];
                o += 1;
                i += 1;
            }
            h += 1;
        }
        t += 1;
    }
    let mut l = 0usize;
    while l < 12 {
        let mut i = 0usize;
        while i < 8 {
            sig_out[o] = 0;
            o += 1;
            i += 1;
        }
        let mut c = 0usize;
        while c < 67 {
            i = 0;
            while i < N {
                sig_out[o] = ht_sig[l].0[c][i];
                o += 1;
                i += 1;
            }
            c += 1;
        }
        let mut h = 0usize;
        while h < 5 {
            i = 0;
            while i < N {
                sig_out[o] = ht_sig[l].1[h][i];
                o += 1;
                i += 1;
            }
            h += 1;
        }
        l += 1;
    }
    debug_assert_eq!(o, SIG_LEN);
}

/// Sign `msg` into `sig_out` (exact `SIG_LEN` bytes, caller buffer).
/// Composes [`pre_sign`] + trees + [`serialize_sig`]; threaded signers
/// produce byte-identical output through the same pieces.
///
/// # Example
///
/// ```rust
/// use hypg_ds::{ds_keygen, ds_sign, ds_verify, SIG_LEN};
///
/// let (pk, sk) = ds_keygen(&[0x43u8; 32]);
/// let mut sig = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
/// ds_sign(&sk, b"hello hypg-ds", &mut sig);
/// assert!(ds_verify(&pk, b"hello hypg-ds", &sig[..]));
/// assert!(!ds_verify(&pk, b"other", &sig[..]));
/// ```
#[allow(clippy::many_single_char_names)]
pub fn ds_sign(sk: &SigSk, msg: &[u8], sig_out: &mut [u8; SIG_LEN]) {
    let ctx = pre_sign(sk, msg);
    let fors_sig = fors::fors_sign(&ctx.pubseed, &ctx.esk, &ctx.fors_idx);
    let fors_pk = fors::fors_verify(&ctx.pubseed, &ctx.fors_idx, &fors_sig);
    let ht_sig = hypertree::ht_sign(&ctx.pubseed, &ctx.esk, ctx.tree_idx, ctx.leaf, &fors_pk);
    serialize_sig(&ctx.r, &fors_sig, &ht_sig, sig_out);
}

/// Verify: `false` on any malformation (length checked first, public).
#[allow(clippy::many_single_char_names)]
#[must_use]
pub fn ds_verify(pk: &SigPk, msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != SIG_LEN {
        return false;
    }
    let mut root = [0u8; N];
    let mut pubseed = [0u8; N];
    let mut i = 0usize;
    while i < N {
        root[i] = pk.0[i];
        pubseed[i] = pk.0[N + i];
        i += 1;
    }
    // Parse (public offsets).
    let mut r = [0u8; N];
    i = 0;
    while i < N {
        r[i] = sig[i];
        i += 1;
    }
    let md = digest(&r, &pubseed, &root, msg);
    let (fors_idx, tree_idx, leaf) = split(&md);
    let mut o = N;
    let mut fors_sig: ForsSig = [([0u8; N], [[0u8; N]; 7]); FORS_K];
    let mut t = 0usize;
    while t < FORS_K {
        i = 0;
        while i < N {
            fors_sig[t].0[i] = sig[o];
            o += 1;
            i += 1;
        }
        let mut h = 0usize;
        while h < 7 {
            i = 0;
            while i < N {
                fors_sig[t].1[h][i] = sig[o];
                o += 1;
                i += 1;
            }
            h += 1;
        }
        t += 1;
    }
    let fors_pk = fors::fors_verify(&pubseed, &fors_idx, &fors_sig);
    let mut ht_sig: [LayerSig; 12] = [([[0u8; N]; 67], [[0u8; N]; 5]); 12];
    let mut l = 0usize;
    while l < 12 {
        // Reserved index field: must be zero (non-malleability — an
        // attacker-flippable ignored field would break SUS).
        let mut pad = 0u8;
        let mut i = 0usize;
        while i < 8 {
            pad |= sig[o];
            o += 1;
            i += 1;
        }
        if pad != 0 {
            return false;
        }
        let mut c = 0usize;
        while c < 67 {
            i = 0;
            while i < N {
                ht_sig[l].0[c][i] = sig[o];
                o += 1;
                i += 1;
            }
            c += 1;
        }
        let mut h = 0usize;
        while h < 5 {
            i = 0;
            while i < N {
                ht_sig[l].1[h][i] = sig[o];
                o += 1;
                i += 1;
            }
            h += 1;
        }
        l += 1;
    }
    let root2 = hypertree::ht_verify(&pubseed, tree_idx, leaf, &fors_pk, &ht_sig);
    // Constant-time root comparison.
    hypg_core::ct::ct_eq(&root2, &root) == 1
}

/// Length sanity (public, testable).
#[must_use]
pub const fn sizes_ok() -> bool {
    SIG_LEN == N + FORS_K * 8 * N + 12 * (8 + 67 * N + 5 * N) && SIG_PK_LEN == 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_hold() {
        assert!(sizes_ok());
    }
    #[test]
    fn round_trip() {
        let (pk, sk) = ds_keygen(&[0x42u8; N]);
        let mut sig = [0u8; SIG_LEN];
        ds_sign(&sk, b"hello hypg-ds", &mut sig);
        assert!(ds_verify(&pk, b"hello hypg-ds", &sig));
    }

    #[test]
    fn tamper_rejects() {
        let (pk, sk) = ds_keygen(&[0x42u8; N]);
        let mut sig = [0u8; SIG_LEN];
        ds_sign(&sk, b"message", &mut sig);
        // Flip each region once: R, FORS leaf, WOTS byte, auth path, pad.
        for pos in [0usize, 40, 8000, 20000, 35455] {
            let mut bad = sig;
            bad[pos] ^= 0x01;
            assert!(!ds_verify(&pk, b"message", &bad), "forgery at {pos}");
        }
        // Wrong message / wrong key / truncated.
        assert!(!ds_verify(&pk, b"other", &sig));
        let (pk2, _) = ds_keygen(&[0x43u8; N]);
        assert!(!ds_verify(&pk2, b"message", &sig));
        assert!(!ds_verify(&pk, b"message", &sig[..SIG_LEN - 1]));
        assert!(!ds_verify(&pk, b"message", b"short"));
    }

    #[test]
    fn determinism() {
        let (_, sk) = ds_keygen(&[0x42u8; N]);
        let mut s1 = [0u8; SIG_LEN];
        let mut s2 = [0u8; SIG_LEN];
        ds_sign(&sk, b"same", &mut s1);
        ds_sign(&sk, b"same", &mut s2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn sk_zeroize() {
        let (_, mut sk) = ds_keygen(&[0x42u8; N]);
        sk.zeroize();
        assert_eq!(sk.0, [0u8; SIG_SK_LEN]);
    }

    #[test]
    fn split_bit_exactness() {
        // Hand-computed vector (`md_bit` is LSB-first within a byte):
        // `md[0] = 0xA5` → `fors[0] = 0b0100101 = 37`, `fors[1] = 1`;
        // `md[26] = 0x04` sets tree bit 210 → `tree_idx = 1`;
        // `md[33] = 0xC0` sets leaf bits 270,271 → `leaf = 3`.
        let mut md = [0u8; 64];
        md[0] = 0xA5;
        md[26] = 0x04;
        md[33] = 0xC0;
        let (fors, tree_idx, leaf) = split(&md);
        assert_eq!(fors[0], 37);
        assert_eq!(fors[1], 1);
        let mut t = 2usize;
        while t < FORS_K {
            assert_eq!(fors[t], 0);
            t += 1;
        }
        assert_eq!(tree_idx, 1);
        assert_eq!(leaf, 3);
        // All-ones digest → maximal indices (bounds, no truncation).
        let (fors_max, tree_max, leaf_max) = split(&[0xFFu8; 64]);
        let mut t = 0usize;
        while t < FORS_K {
            assert_eq!(fors_max[t], 127);
            t += 1;
        }
        assert_eq!(tree_max, (1u64 << 60) - 1);
        assert_eq!(leaf_max, 31);
    }
}
