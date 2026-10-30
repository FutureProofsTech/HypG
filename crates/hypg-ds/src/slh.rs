//! SLH composition: `R` randomizer, message digest split, sign/verify.
//!
//! `md[64]` via BLAKE3 streaming over `R ‖ pubseed ‖ root ‖ msg-digest`
//! (arbitrary message lengths, no concatenation buffers). Digest bits:
//! FORS `35×9`, tree `68`, leaf `4` (387 bits of 512). Deterministic:
//! same `(sk, msg)` → same `sig`.

use hypg_core::b3::{b3_hash, Hasher};
use hypg_core::caprf::ca_expand;
use hypg_core::ct::zeroize;

use crate::fors::{self, ForsSig};
use crate::hypertree::{self, LayerSig};
use crate::params::{D, FORS_A, FORS_K, H, HP, N, SIG_LEN, SIG_PK_LEN, SIG_SK_LEN, WOTS_LEN};

const D_ADDRND: &[u8] = b"HYP-G/v07/ds-addrnd";
const D_MSGHASH: &[u8] = b"HYP-G/v07/ds-msghash";
const D_PUBSEED: &[u8] = b"HYP-G/v07/ds-pubseed";
const D_PRF: &[u8] = b"HYP-G/v07/ds-prf";

/// Public key: `root(32) || pubseed(32)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigPk(pub [u8; SIG_PK_LEN]);

/// Secret key: `esk(32) || prf(32) || pubseed(32) || root(32)`.
///
/// Not `Copy`; `Debug` is redacted, equality is constant-time, and `Drop`
/// best-effort zeroizes the bytes.
#[derive(Clone)]
pub struct SigSk(pub [u8; SIG_SK_LEN]);

impl core::fmt::Debug for SigSk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigSk { .. }")
    }
}

impl PartialEq for SigSk {
    fn eq(&self, other: &Self) -> bool {
        hypg_core::ct::ct_eq(&self.0, &other.0) == 1
    }
}
impl Eq for SigSk {}

impl Drop for SigSk {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

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
    let out = h.finalize32();
    zeroize(&mut stream);
    zeroize(&mut mhash);
    out
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

/// Split digest: `FORS_K` FORS indices (`FORS_A` bits each), a
/// `H`-bit tree index, and an `HP`-bit leaf index.
fn split(md: &[u8; 64]) -> ([u32; FORS_K], u128, u32) {
    let mut fors = [0u32; FORS_K];
    let mut t = 0usize;
    while t < FORS_K {
        let mut v = 0u32;
        let mut b = 0usize;
        while b < FORS_A {
            v |= md_bit(md, t * FORS_A + b) << b;
            b += 1;
        }
        fors[t] = v;
        t += 1;
    }
    let tree_start = FORS_K * FORS_A;
    let mut tree_idx = 0u128;
    let mut b = 0usize;
    while b < H {
        tree_idx |= u128::from(md_bit(md, tree_start + b)) << b;
        b += 1;
    }
    let leaf_start = tree_start + H;
    let mut leaf = 0u32;
    b = 0;
    while b < HP {
        leaf |= md_bit(md, leaf_start + b) << b;
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
    let out = (SigPk(pk), SigSk(sk));
    zeroize(&mut prf);
    zeroize(&mut sk);
    out
}

/// Signing prelude: hedged randomizer, digest split, and the secret key
/// material a signer needs. Pure function of `(sk, msg)`; the returned
/// components feed independent parallel units in threaded signers.
///
/// The master secret `esk` is private (accessor [`PreSign::esk`]); `Debug`
/// is redacted and `Drop` best-effort zeroizes it.
pub struct PreSign {
    /// Hedged randomizer `R`.
    pub r: [u8; N],
    /// Master secret seed.
    esk: [u8; N],
    /// Public seed.
    pub pubseed: [u8; N],
    /// FORS leaf indices (`FORS_K × FORS_A` bits).
    pub fors_idx: [u32; FORS_K],
    /// Hypertree selector (`H = 68` bits).
    pub tree_idx: u128,
    /// Bottom-layer leaf index (`HP` bits).
    pub leaf: u32,
}

impl PreSign {
    /// Master secret seed (borrowed; never rendered by `Debug`).
    #[must_use]
    pub const fn esk(&self) -> &[u8; N] {
        &self.esk
    }
}

impl core::fmt::Debug for PreSign {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreSign")
            .field("r", &self.r)
            .field("pubseed", &self.pubseed)
            .field("fors_idx", &self.fors_idx)
            .field("tree_idx", &self.tree_idx)
            .field("leaf", &self.leaf)
            .finish_non_exhaustive()
    }
}

impl Drop for PreSign {
    fn drop(&mut self) {
        zeroize(&mut self.esk);
    }
}

/// Compute [`PreSign`] (fast: two hashes + splits, no trees).
#[must_use]
pub fn pre_sign(sk: &SigSk, msg: &[u8]) -> PreSign {
    let (mut esk, mut prf_seed, pubseed, root) = sk_parts(&sk.0);
    let r = randomizer(&prf_seed, msg);
    zeroize(&mut prf_seed);
    let md = digest(&r, &pubseed, &root, msg);
    let (fors_idx, tree_idx, leaf) = split(&md);
    let ctx = PreSign { r, esk, pubseed, fors_idx, tree_idx, leaf };
    zeroize(&mut esk);
    ctx
}

/// Serialize `R ‖ FORS ×FORS_K ‖ layers ×D` into the exact `SIG_LEN`
/// buffer. Shared by serial and threaded signers (single serialization
/// truth).
#[allow(clippy::many_single_char_names)]
pub fn serialize_sig(
    r: &[u8; N],
    fors_sig: &ForsSig,
    ht_sig: &[LayerSig; D],
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
        while h < FORS_A {
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
    while l < D {
        let mut i = 0usize;
        while i < 8 {
            sig_out[o] = 0;
            o += 1;
            i += 1;
        }
        let mut c = 0usize;
        while c < WOTS_LEN {
            i = 0;
            while i < N {
                sig_out[o] = ht_sig[l].0[c][i];
                o += 1;
                i += 1;
            }
            c += 1;
        }
        let mut h = 0usize;
        while h < HP {
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

/// Best-effort erasure for a FORS signature (contains revealed secret
/// leaves and local auth-path copies).
fn zeroize_fors(sig: &mut ForsSig) {
    let mut t = 0usize;
    while t < FORS_K {
        zeroize(&mut sig[t].0);
        let mut h = 0usize;
        while h < FORS_A {
            zeroize(&mut sig[t].1[h]);
            h += 1;
        }
        t += 1;
    }
}

/// Best-effort erasure for a hypertree signature's local copy.
fn zeroize_layers(sig: &mut [LayerSig; D]) {
    let mut l = 0usize;
    while l < D {
        let mut c = 0usize;
        while c < WOTS_LEN {
            zeroize(&mut sig[l].0[c]);
            c += 1;
        }
        let mut h = 0usize;
        while h < HP {
            zeroize(&mut sig[l].1[h]);
            h += 1;
        }
        l += 1;
    }
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
    let mut fors_sig = fors::fors_sign(&ctx.pubseed, ctx.esk(), &ctx.fors_idx);
    let fors_pk = fors::fors_verify(&ctx.pubseed, &ctx.fors_idx, &fors_sig);
    let mut ht_sig = hypertree::ht_sign(&ctx.pubseed, ctx.esk(), ctx.tree_idx, ctx.leaf, &fors_pk);
    serialize_sig(&ctx.r, &fors_sig, &ht_sig, sig_out);
    zeroize_fors(&mut fors_sig);
    zeroize_layers(&mut ht_sig);
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
    let mut fors_sig: ForsSig = [([0u8; N], [[0u8; N]; FORS_A]); FORS_K];
    let mut t = 0usize;
    while t < FORS_K {
        i = 0;
        while i < N {
            fors_sig[t].0[i] = sig[o];
            o += 1;
            i += 1;
        }
        let mut h = 0usize;
        while h < FORS_A {
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
    let mut ht_sig: [LayerSig; D] = [([[0u8; N]; WOTS_LEN], [[0u8; N]; HP]); D];
    let mut l = 0usize;
    while l < D {
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
        while c < WOTS_LEN {
            i = 0;
            while i < N {
                ht_sig[l].0[c][i] = sig[o];
                o += 1;
                i += 1;
            }
            c += 1;
        }
        let mut h = 0usize;
        while h < HP {
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
    SIG_LEN == N + FORS_K * (FORS_A + 1) * N + D * (8 + WOTS_LEN * N + HP * N) && SIG_PK_LEN == 64
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
        let layer0 = N + FORS_K * (FORS_A + 1) * N;
        let auth0 = layer0 + 8 + WOTS_LEN * N;
        for pos in [0usize, 40, layer0, auth0, SIG_LEN - 1] {
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
        // `md_bit` is LSB-first within a byte. Set one bit per field and
        // check the three extracted values independently.
        let mut md = [0u8; 64];
        let tree_start = FORS_K * FORS_A;
        let leaf_start = tree_start + H;
        md[0] = 0x01; // FORS[0] bit 0
        md[tree_start / 8] |= 1 << (tree_start % 8); // tree bit 0
        md[leaf_start / 8] |= 1 << (leaf_start % 8); // leaf bit 0
        let (fors, tree_idx, leaf) = split(&md);
        assert_eq!(fors[0], 1);
        let mut t = 1usize;
        while t < FORS_K {
            assert_eq!(fors[t], 0);
            t += 1;
        }
        assert_eq!(tree_idx, 1);
        assert_eq!(leaf, 1);
        // All-ones digest → maximal indices (bounds, no truncation).
        let (fors_max, tree_max, leaf_max) = split(&[0xFFu8; 64]);
        let mut t = 0usize;
        while t < FORS_K {
            assert_eq!(fors_max[t], (1u32 << FORS_A) - 1);
            t += 1;
        }
        assert_eq!(tree_max, (1u128 << H) - 1);
        assert_eq!(leaf_max, (1u32 << HP) - 1);
    }
}
