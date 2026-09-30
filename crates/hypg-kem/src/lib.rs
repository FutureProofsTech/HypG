//! `hypg-kem`: NIST-style IND-CCA2 KEM over `hypg-core`.
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`.
//!
//! ## v0.4 trapdoor (Module-LWE, Kyber-class; unchanged from v0.3)
//!
//! Module rank `k = 2`, ring `R_q = Z_q[X]/(X^256+1)`, `q = 2^12`.
//! Public key `pk = seed_a(32) || pack12(b_vec)(768)` with
//! `b = A·s + e` (`A` is `2×2` uniform from `seed_a`).
//! Ciphertext `ct = pack10(c1_vec)(640) || pack5(c2)(160)` with
//! `c1 = A^T·r + e1`, `c2 = b^T·r + e2 + encode(m)` (1 bit/coeff).
//! Fujisaki-Okamoto with implicit rejection: `r,e1,e2 = CA-PRF(m, pk)`,
//! `ss = KDF(m || ct || pk_hash)`.
//!
//! The CA stays on every path: all randomness is expanded through
//! `CA-PRF` (32 branchless CA rounds + BLAKE3 outer hash, uniform in the
//! ROM). Recovering `m` from `(pk, ct)` requires solving 512-dimensional
//! Module-LWE, not evaluating a public KDF.
//!
//! v0.7: all hashes/XOF/KDF moved from SHA3 to BLAKE3 (domains now
//! `HYP-G/v07/...`); lattice parameters unchanged.
//!
//! Parameters target Kyber-512-class hardness with power-of-two `q`
//! (branchless mask-only reduction, no Barrett division).
//! **Prototype**: pending lattice-estimator confirmation + audit.
//! See `docs/spec.md`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use hypg_core::b3::{b3_hash, b3_kdf};
use hypg_core::caprf::ca_expand;
use hypg_core::ct::{ct_eq, ct_select};
use hypg_core::params::{
    B_PACKED_LEN, C1_VEC_PACKED_LEN, C2_PACKED_LEN, CBD_RAND_LEN, CT_LEN, FAKE_LEN, MODULE_K,
    MSG_LEN, PK_LEN, POLY_PACKED_LEN, SEED_LEN, SK_LEN, SS_LEN,
};
use hypg_core::poly::{cbd_eta2, dot2, Poly};

// Domain separators (all public, ASCII, unique per use).
const D_SEED_A: &[u8] = b"HYP-G/v07/seed-a";
const D_SEC_S: &[u8] = b"HYP-G/v07/sec-s";
const D_SEC_E: &[u8] = b"HYP-G/v07/sec-e";
const D_POLY_A: &[u8] = b"HYP-G/v07/poly-a";
const D_R: &[u8] = b"HYP-G/v07/rand-r";
const D_E1: &[u8] = b"HYP-G/v07/rand-e1";
const D_E2: &[u8] = b"HYP-G/v07/rand-e2";
const D_FAKE: &[u8] = b"HYP-G/v07/fake";
const D_RSEED: &[u8] = b"HYP-G/v07/r-seed";
const D_SS: &[u8] = b"HYP-G/v07/ss";
const D_REJECT: &[u8] = b"HYP-G/v07/reject";

/// Public key: `seed_a(32) || pack12(b_vec)(768)` = 800 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PK_LEN]);

/// Secret key: `seed(32) || fake(32) || pk(800)` = 864 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKey(pub [u8; SK_LEN]);

/// Ciphertext: `pack10(c1_vec)(640) || pack5(c2)(160)` = 800 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext(pub [u8; CT_LEN]);

/// Shared secret: 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedSecret(pub [u8; SS_LEN]);

impl PublicKey {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PK_LEN] {
        &self.0
    }
    /// Parse from bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; PK_LEN]) -> Self {
        Self(b)
    }
}

impl SecretKey {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SK_LEN] {
        &self.0
    }
    /// Parse from bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; SK_LEN]) -> Self {
        Self(b)
    }
    /// Copy of the master seed (bytes `0..32`).
    #[must_use]
    pub fn seed_copy(&self) -> [u8; SEED_LEN] {
        let mut s = [0u8; SEED_LEN];
        let mut i = 0usize;
        while i < SEED_LEN {
            s[i] = self.0[i];
            i += 1;
        }
        s
    }
    /// Copy of the implicit-rejection fake key (bytes `32..64`).
    #[must_use]
    pub fn fake_copy(&self) -> [u8; FAKE_LEN] {
        let mut f = [0u8; FAKE_LEN];
        let mut i = 0usize;
        while i < FAKE_LEN {
            f[i] = self.0[SEED_LEN + i];
            i += 1;
        }
        f
    }
    /// Copy of the embedded public key.
    #[must_use]
    pub fn public_copy(&self) -> [u8; PK_LEN] {
        let mut p = [0u8; PK_LEN];
        let mut i = 0usize;
        while i < PK_LEN {
            p[i] = self.0[SEED_LEN + FAKE_LEN + i];
            i += 1;
        }
        p
    }
    /// Best-effort in-place erasure (safe-Rust `zeroize`, see
    /// `hypg_core::ct::zeroize`). Call before dropping key material;
    /// see `docs/deployment.md` for `mlock`/`mlockall` guidance the
    /// library itself cannot provide (`no_std`, no OS interface).
    pub fn zeroize(&mut self) {
        hypg_core::ct::zeroize(&mut self.0);
    }
}

impl Ciphertext {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CT_LEN] {
        &self.0
    }
    /// Parse from bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; CT_LEN]) -> Self {
        Self(b)
    }
}

impl SharedSecret {
    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SS_LEN] {
        &self.0
    }
    /// Best-effort in-place erasure (see `SecretKey::zeroize`).
    pub fn zeroize(&mut self) {
        hypg_core::ct::zeroize(&mut self.0);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (safe, branchless where secrets involved).
// ---------------------------------------------------------------------------

/// Split `pk` into `(seed_a, b_vec)`.
fn parse_pk(pk: &[u8; PK_LEN]) -> ([u8; SEED_LEN], [Poly; MODULE_K]) {
    let mut seed_a = [0u8; SEED_LEN];
    let mut i = 0usize;
    while i < SEED_LEN {
        seed_a[i] = pk[i];
        i += 1;
    }
    let mut b = [Poly::zero(); MODULE_K];
    let mut k = 0usize;
    while k < MODULE_K {
        let mut packed = [0u8; POLY_PACKED_LEN];
        let mut j = 0usize;
        while j < POLY_PACKED_LEN {
            packed[j] = pk[SEED_LEN + k * POLY_PACKED_LEN + j];
            j += 1;
        }
        b[k] = Poly::unpack12(&packed);
        k += 1;
    }
    (seed_a, b)
}

/// Public matrix `A` (`2×2` polys) from `seed_a` via `CA-PRF`.
/// Layout `mat[row][col]`; encryption uses the transpose.
fn poly_a_mat(seed_a: &[u8; SEED_LEN]) -> [[Poly; MODULE_K]; MODULE_K] {
    let mut buf = [0u8; MODULE_K * MODULE_K * POLY_PACKED_LEN];
    ca_expand(&mut buf, seed_a, D_POLY_A);
    let mut mat = [[Poly::zero(); MODULE_K]; MODULE_K];
    let mut r = 0usize;
    while r < MODULE_K {
        let mut c = 0usize;
        while c < MODULE_K {
            let mut packed = [0u8; POLY_PACKED_LEN];
            let mut j = 0usize;
            while j < POLY_PACKED_LEN {
                packed[j] = buf[(r * MODULE_K + c) * POLY_PACKED_LEN + j];
                j += 1;
            }
            mat[r][c] = Poly::unpack12(&packed);
            c += 1;
        }
        r += 1;
    }
    mat
}

/// Secret vector `s` from master seed via `CA-PRF` + `CBD(eta=2)`.
fn poly_s_vec(master: &[u8; SEED_LEN]) -> [Poly; MODULE_K] {
    let mut buf = [0u8; MODULE_K * CBD_RAND_LEN];
    ca_expand(&mut buf, master, D_SEC_S);
    let mut out = [Poly::zero(); MODULE_K];
    let mut k = 0usize;
    while k < MODULE_K {
        let mut r128 = [0u8; CBD_RAND_LEN];
        let mut j = 0usize;
        while j < CBD_RAND_LEN {
            r128[j] = buf[k * CBD_RAND_LEN + j];
            j += 1;
        }
        out[k] = cbd_eta2(&r128);
        k += 1;
    }
    out
}

/// Error vector `e` from master seed via `CA-PRF` + `CBD(eta=2)`.
fn poly_e_vec(master: &[u8; SEED_LEN]) -> [Poly; MODULE_K] {
    let mut buf = [0u8; MODULE_K * CBD_RAND_LEN];
    ca_expand(&mut buf, master, D_SEC_E);
    let mut out = [Poly::zero(); MODULE_K];
    let mut k = 0usize;
    while k < MODULE_K {
        let mut r128 = [0u8; CBD_RAND_LEN];
        let mut j = 0usize;
        while j < CBD_RAND_LEN {
            r128[j] = buf[k * CBD_RAND_LEN + j];
            j += 1;
        }
        out[k] = cbd_eta2(&r128);
        k += 1;
    }
    out
}

/// `seed_a` from master seed via `CA-PRF`.
fn derive_seed_a(master: &[u8; SEED_LEN]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    ca_expand(&mut out, master, D_SEED_A);
    out
}

/// Single `CBD` poly from 128-byte buffer helper.
fn cbd_from_buf(buf128: &[u8; CBD_RAND_LEN]) -> Poly {
    cbd_eta2(buf128)
}

/// Encryption randomness `(r_vec, e1_vec, e2)` from `(m, pk)` via `CA-PRF`
/// (FO `G` oracle). Deterministic, bound to both inputs.
#[allow(clippy::type_complexity)]
fn derive_rand(m: &[u8; MSG_LEN], pk: &[u8; PK_LEN]) -> ([Poly; MODULE_K], [Poly; MODULE_K], Poly) {
    let mut rseed = [0u8; SEED_LEN];
    {
        let mut buf = [0u8; 896];
        let mut o = 0usize;
        let mut i = 0usize;
        while i < MSG_LEN {
            buf[o] = m[i];
            o += 1;
            i += 1;
        }
        i = 0;
        while i < PK_LEN {
            buf[o] = pk[i];
            o += 1;
            i += 1;
        }
        i = 0;
        while i < D_RSEED.len() {
            buf[o] = D_RSEED[i];
            o += 1;
            i += 1;
        }
        b3_hash(&buf[..o], &mut rseed);
    }
    let mut br = [0u8; MODULE_K * CBD_RAND_LEN];
    let mut b1 = [0u8; MODULE_K * CBD_RAND_LEN];
    let mut b2 = [0u8; CBD_RAND_LEN];
    ca_expand(&mut br, &rseed, D_R);
    ca_expand(&mut b1, &rseed, D_E1);
    ca_expand(&mut b2, &rseed, D_E2);
    let mut r = [Poly::zero(); MODULE_K];
    let mut e1 = [Poly::zero(); MODULE_K];
    let mut k = 0usize;
    while k < MODULE_K {
        let mut rr = [0u8; CBD_RAND_LEN];
        let mut ee = [0u8; CBD_RAND_LEN];
        let mut j = 0usize;
        while j < CBD_RAND_LEN {
            rr[j] = br[k * CBD_RAND_LEN + j];
            ee[j] = b1[k * CBD_RAND_LEN + j];
            j += 1;
        }
        r[k] = cbd_from_buf(&rr);
        e1[k] = cbd_from_buf(&ee);
        k += 1;
    }
    (r, e1, cbd_from_buf(&b2))
}

/// Raw PKE encrypt: `(c1_vec, c2)`. `m` is the 32-byte FO message.
fn pke_encrypt(
    mat: &[[Poly; MODULE_K]; MODULE_K],
    b_vec: &[Poly; MODULE_K],
    m: &[u8; MSG_LEN],
    r: &[Poly; MODULE_K],
    e1: &[Poly; MODULE_K],
    e2: &Poly,
) -> ([Poly; MODULE_K], Poly) {
    // `c1 = A^T·r + e1`.
    let mut c1 = [Poly::zero(); MODULE_K];
    let mut row = 0usize;
    while row < MODULE_K {
        // Row `row` of `A^T` is column `row` of `A`.
        let t = mat[0][row].mul(&r[0]).add(&mat[1][row].mul(&r[1]));
        c1[row] = t.add(&e1[row]);
        row += 1;
    }
    // `c2 = b^T·r + e2 + encode(m)`.
    let bt_r = dot2(&b_vec[0], &b_vec[1], &r[0], &r[1]);
    let c2 = bt_r.add(e2).add(&Poly::encode(m));
    (c1, c2)
}

/// Pack `(c1_vec, c2)` with compression into 800-byte `ct`.
fn pack_ct(c1: &[Poly; MODULE_K], c2: &Poly) -> [u8; CT_LEN] {
    let mut ct = [0u8; CT_LEN];
    let mut k = 0usize;
    while k < MODULE_K {
        let p = c1[k].compress10().pack10();
        let mut j = 0usize;
        while j < p.len() {
            ct[k * p.len() + j] = p[j];
            j += 1;
        }
        k += 1;
    }
    let p2 = c2.compress5().pack5();
    let mut j = 0usize;
    while j < p2.len() {
        ct[C1_VEC_PACKED_LEN + j] = p2[j];
        j += 1;
    }
    ct
}

/// Unpack + decompress `ct` into `(c1_vec, c2)` 12-bit polys.
#[allow(clippy::type_complexity)]
fn unpack_ct(ct: &[u8; CT_LEN]) -> ([Poly; MODULE_K], Poly) {
    use hypg_core::params::{C1_PACKED_LEN, C2_PACKED_LEN as C2PL};
    use hypg_core::poly::{Poly10, Poly5};
    let mut c1 = [Poly::zero(); MODULE_K];
    let mut k = 0usize;
    while k < MODULE_K {
        let mut b = [0u8; C1_PACKED_LEN];
        let mut j = 0usize;
        while j < C1_PACKED_LEN {
            b[j] = ct[k * C1_PACKED_LEN + j];
            j += 1;
        }
        c1[k] = Poly10::unpack10(&b).decompress();
        k += 1;
    }
    let mut b2 = [0u8; C2PL];
    let mut j = 0usize;
    while j < C2PL {
        b2[j] = ct[C1_VEC_PACKED_LEN + j];
        j += 1;
    }
    (c1, Poly5::unpack5(&b2).decompress())
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Generate `(pk, sk)` deterministically from a 32-byte seed.
///
/// The caller supplies randomness (e.g. OS RNG). No RNG inside `no_std` lib.
///
/// # Example
///
/// ```rust
/// use hypg_kem::{decaps, encaps, keygen};
///
/// let (pk, sk) = keygen(&[0x42u8; 32]);
/// let (ct, ss1) = encaps(&pk, &[0x07u8; 32]);
/// let ss2 = decaps(&sk, &ct);
/// assert_eq!(ss1, ss2);
/// ```
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn keygen(seed: &[u8; SEED_LEN]) -> (PublicKey, SecretKey) {
    let seed_a = derive_seed_a(seed);
    let mat = poly_a_mat(&seed_a);
    let s = poly_s_vec(seed);
    let e = poly_e_vec(seed);
    // `b = A·s + e`.
    let mut b = [Poly::zero(); MODULE_K];
    let mut row = 0usize;
    while row < MODULE_K {
        let t = dot2(&mat[row][0], &mat[row][1], &s[0], &s[1]);
        b[row] = t.add(&e[row]);
        row += 1;
    }
    let mut pk_bytes = [0u8; PK_LEN];
    let mut i = 0usize;
    while i < SEED_LEN {
        pk_bytes[i] = seed_a[i];
        i += 1;
    }
    let mut k = 0usize;
    while k < MODULE_K {
        let bp = b[k].pack12();
        let mut j = 0usize;
        while j < bp.len() {
            pk_bytes[SEED_LEN + k * bp.len() + j] = bp[j];
            j += 1;
        }
        k += 1;
    }
    let mut fake = [0u8; FAKE_LEN];
    ca_expand(&mut fake, seed, D_FAKE);
    let mut sk_bytes = [0u8; SK_LEN];
    let mut a = 0usize;
    while a < SEED_LEN {
        sk_bytes[a] = seed[a];
        a += 1;
    }
    let mut f = 0usize;
    while f < FAKE_LEN {
        sk_bytes[SEED_LEN + f] = fake[f];
        f += 1;
    }
    let mut p = 0usize;
    while p < PK_LEN {
        sk_bytes[SEED_LEN + FAKE_LEN + p] = pk_bytes[p];
        p += 1;
    }
    (PublicKey(pk_bytes), SecretKey(sk_bytes))
}

/// Encapsulate to `pk` with caller-supplied `coins` (32 B FO message).
/// Deterministic for a given `(pk, coins)` — suitable for KATs.
#[must_use]
pub fn encaps(pk: &PublicKey, coins: &[u8; SEED_LEN]) -> (Ciphertext, SharedSecret) {
    let (seed_a, b_vec) = parse_pk(&pk.0);
    let mat = poly_a_mat(&seed_a);
    let (r, e1, e2) = derive_rand(coins, &pk.0);
    let (c1, c2) = pke_encrypt(&mat, &b_vec, coins, &r, &e1, &e2);
    let ct = pack_ct(&c1, &c2);
    let mut pk_hash = [0u8; 32];
    b3_hash(&pk.0, &mut pk_hash);
    let mut ss = [0u8; SS_LEN];
    b3_kdf(&mut ss, &[coins.as_slice(), ct.as_slice(), pk_hash.as_slice()], D_SS);
    (Ciphertext(ct), SharedSecret(ss))
}

/// Decapsulate with implicit rejection. Never fails; wrong `ct` yields
/// a pseudorandom `ss` derived from the fake key (constant-time select).
#[must_use]
pub fn decaps(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
    let master = sk.seed_copy();
    let fake = sk.fake_copy();
    let pk = sk.public_copy();

    let (seed_a, b_vec) = parse_pk(&pk);
    let mat = poly_a_mat(&seed_a);
    let s = poly_s_vec(&master);

    // Decrypt: `v = c2 - s^T·c1`, decode to `m'`.
    let (c1, c2) = unpack_ct(&ct.0);
    let st_c1 = dot2(&s[0], &s[1], &c1[0], &c1[1]);
    let m_cand = c2.sub(&st_c1).decode();

    // Re-encryption check (FO): recompute `ct'` from `m'`.
    let (r2, e12, e22) = derive_rand(&m_cand, &pk);
    let (c1c, c2c) = pke_encrypt(&mat, &b_vec, &m_cand, &r2, &e12, &e22);
    let ct_check = pack_ct(&c1c, &c2c);
    let ok = ct_eq(&ct_check, &ct.0);

    let mut pk_hash = [0u8; 32];
    b3_hash(&pk, &mut pk_hash);
    let mut ss_ok = [0u8; SS_LEN];
    b3_kdf(&mut ss_ok, &[m_cand.as_slice(), ct.0.as_slice(), pk_hash.as_slice()], D_SS);
    let mut ss_rej = [0u8; SS_LEN];
    b3_kdf(&mut ss_rej, &[fake.as_slice(), ct.0.as_slice()], D_REJECT);

    let mut ss = [0u8; SS_LEN];
    ct_select(&mut ss, &ss_ok, &ss_rej, ok);
    SharedSecret(ss)
}

/// Length / layout sanity (public, testable).
#[must_use]
pub const fn sizes_ok() -> bool {
    PK_LEN == SEED_LEN + B_PACKED_LEN && CT_LEN == C1_VEC_PACKED_LEN + C2_PACKED_LEN
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
        let seed = [0x42u8; 32];
        let coins = [0x11u8; 32];
        let (pk, sk) = keygen(&seed);
        let (ct, ss1) = encaps(&pk, &coins);
        let ss2 = decaps(&sk, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn round_trip_many() {
        let tags: [u8; 6] = [0x00, 0x01, 0x42, 0xA5, 0x7F, 0xFF];
        for t in tags {
            let seed = [t; 32];
            let coins = [t.wrapping_add(0x33); 32];
            let (pk, sk) = keygen(&seed);
            let (ct, ss1) = encaps(&pk, &coins);
            let ss2 = decaps(&sk, &ct);
            assert_eq!(ss1, ss2, "round-trip failed for tag {t:#04x}");
        }
        let seed = [0x5Au8; 32];
        let mut coins = [0u8; 32];
        let mut idx: u32 = 0;
        while idx < 32 {
            coins[idx as usize] = u8::try_from(idx).unwrap_or(0xFF);
            idx += 1;
        }
        let (pk, sk) = keygen(&seed);
        let (ct, ss1) = encaps(&pk, &coins);
        assert_eq!(ss1, decaps(&sk, &ct));
    }

    #[test]
    fn tampered_ct_rejects() {
        let seed = [0x42u8; 32];
        let coins = [0x11u8; 32];
        let (pk, sk) = keygen(&seed);
        let (mut ct, ss1) = encaps(&pk, &coins);
        ct.0[0] ^= 0x01;
        let ss2 = decaps(&sk, &ct);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn wrong_key_rejects() {
        let (pk, _) = keygen(&[0x11u8; 32]);
        let (_, sk2) = keygen(&[0x22u8; 32]);
        let (ct, ss1) = encaps(&pk, &[0x33u8; 32]);
        let ss2 = decaps(&sk2, &ct);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn determinism() {
        let seed = [9u8; 32];
        let (pk1, sk1) = keygen(&seed);
        let (pk2, sk2) = keygen(&seed);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn encaps_deterministic() {
        // FO randomness is derived, not sampled: same `(pk, coins)` →
        // same `(ct, ss)` (KAT reliance); different coins → different `ct`.
        let (pk, _) = keygen(&[0x42u8; 32]);
        let (ct1, ss1) = encaps(&pk, &[0x11u8; 32]);
        let (ct2, ss2) = encaps(&pk, &[0x11u8; 32]);
        assert_eq!((ct1, ss1), (ct2, ss2));
        let (ct3, _) = encaps(&pk, &[0x12u8; 32]);
        assert_ne!(ct1, ct3);
    }

    #[test]
    fn zeroize_clears_key_material() {
        let (pk, mut sk) = keygen(&[0x42u8; 32]);
        let (_, mut ss) = encaps(&pk, &[0x11u8; 32]);
        sk.zeroize();
        ss.zeroize();
        assert_eq!(sk.0, [0u8; SK_LEN]);
        assert_eq!(ss.0, [0u8; SS_LEN]);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn failure_rate_zero_in_sample() {
        // 32 pseudo-random trials (module ops are heavier than v0.2 ring;
        // 32 keeps debug CI fast while still catching noise-balance bugs).
        let mut fails = 0u32;
        let mut i = 0u32;
        while i < 32 {
            let seed = {
                let mut s = [0u8; 32];
                let mut k = 0u32;
                while k < 32 {
                    s[k as usize] =
                        (i.wrapping_mul(0x9E37_79B9).wrapping_add(k.wrapping_mul(0x85EB_CA6B)))
                            as u8;
                    k += 1;
                }
                s
            };
            let coins = {
                let mut c = [0u8; 32];
                let mut k = 0u32;
                while k < 32 {
                    c[k as usize] = (i.wrapping_add(0xC2B2_8081).wrapping_add(k)) as u8;
                    k += 1;
                }
                c
            };
            let (pk, sk) = keygen(&seed);
            let (ct, ss1) = encaps(&pk, &coins);
            if ss1 != decaps(&sk, &ct) {
                fails += 1;
            }
            i += 1;
        }
        assert_eq!(fails, 0, "{fails} decapsulation failures in 32 trials");
    }
}
