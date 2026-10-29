//! Normative size and round parameters (`HypG` v2.0 hardened profile).
//!
//! All sizes are fixed at compile time. No dynamic allocation.
//! v2.0 raises the Module-LWE module rank to `k = 4` (dimension 1024),
//! matching the NIST Category 5 *dimension* target while retaining the
//! power-of-two modulus `q = 2^12` for branchless, mask-only reduction.
//! This is a parameter-hardening change, not a security certification.

/// Words in the automaton state: 32 × 8 B = 256 B flat array.
pub const STATE_WORDS: usize = 32;
/// State size in bytes.
pub const STATE_BYTES: usize = 256;
/// Words in the secret micro-code rule tensor.
pub const RULE_WORDS: usize = 8;
/// Fixed number of automaton rounds. Must never depend on secrets.
pub const ROUNDS: usize = 32;

/// Long-term / ephemeral seed length (256-bit entropy minimum).
pub const SEED_LEN: usize = 32;
/// Implicit-rejection fake key length.
pub const FAKE_LEN: usize = 32;
/// Public key length: `seed_a(32) || pack12(b_vec)(1536)`.
pub const PK_LEN: usize = 1568;
/// Ciphertext length: `pack10(c1_vec)(1280) || pack5(c2)(160)`.
pub const CT_LEN: usize = 1440;
/// Shared secret length.
pub const SS_LEN: usize = 32;
/// Secret key length: `seed(32) || fake(32) || pk(1568)`.
pub const SK_LEN: usize = SEED_LEN + FAKE_LEN + PK_LEN;

/// Hash output length (BLAKE3-256).
pub const HASH_LEN: usize = 32;

// --- Module-LWE trapdoor parameters (v2.0, Category-5 dimensions) ---
/// Ring dimension (power of two for `X^n+1`).
pub const POLY_N: usize = 256;
/// Module rank (`k = 4`, so lattice dimension `1024`).
pub const MODULE_K: usize = 4;
/// Cipher modulus `q = 2^12` (power of two: mask-only reduction).
pub const MOD_Q: u16 = 4096;
/// `q` mask for branchless reduction.
pub const MOD_Q_MASK: u16 = 0x0FFF;
/// `q` bit-width.
pub const MOD_Q_BITS: usize = 12;
/// `c1` compressed modulus `2^10`, mask `0x3FF`.
pub const C1_Q: u16 = 1024;
/// `c1` compressed-coefficient mask.
pub const C1_Q_MASK: u16 = 0x03FF;
/// `c1` compressed bit-width.
pub const C1_Q_BITS: usize = 10;
/// `c2` compressed modulus `2^5`, mask `0x1F`.
pub const C2_Q: u16 = 32;
/// `c2` compressed-coefficient mask.
pub const C2_Q_MASK: u16 = 0x001F;
/// `c2` compressed bit-width.
pub const C2_Q_BITS: usize = 5;
/// Packed single-poly 12-bit length: `256*12/8`.
pub const POLY_PACKED_LEN: usize = 384;
/// Packed `b`/`c1`-vector element count note: per-poly 10-bit `320 B`.
pub const C1_PACKED_LEN: usize = 320;
/// Packed `c2` length: `256*5/8`.
pub const C2_PACKED_LEN: usize = 160;
/// Packed `b` vector length: `k * 384`.
pub const B_PACKED_LEN: usize = MODULE_K * POLY_PACKED_LEN;
/// Packed `c1` vector length: `k * 320`.
pub const C1_VEC_PACKED_LEN: usize = MODULE_K * C1_PACKED_LEN;
/// Message bytes (1 bit/coeff over 256 coeffs).
pub const MSG_LEN: usize = 32;
/// Message bits per coefficient (`256*1 = 256`).
pub const MSG_BITS_PER_COEFF: usize = 1;
/// Centered binomial parameter (`eta = 2`, values `-2..=2`).
pub const CBD_ETA: usize = 2;
/// `CBD` random bytes per poly: `256 coeffs * 4 bits = 128 B`.
pub const CBD_RAND_LEN: usize = 128;

// Legacy aliases kept for any external harnesses (v0.2 names).
/// Alias: 12-bit pack length (single poly).
pub const B_SINGLE_PACKED_LEN: usize = POLY_PACKED_LEN;
/// Alias: `c1` per-poly pack length.
pub const C_PACKED_LEN: usize = C1_PACKED_LEN;
/// Alias: compressed mask for `c1` (v0.2 `CT_Q_MASK` name).
pub const CT_Q_MASK: u16 = C1_Q_MASK;
/// Encode shift for 1-bit messages: `bit << 11` (spacing `q/2 = 2048`).
pub const ENCODE_SHIFT: u32 = 11;

// Compile-time guards: fail fast if anyone edits sizes unsafely.
const _: () = {
    assert!(STATE_WORDS * 8 == STATE_BYTES);
    assert!(PK_LEN == SEED_LEN + B_PACKED_LEN);
    assert!(CT_LEN == C1_VEC_PACKED_LEN + C2_PACKED_LEN);
    assert!(SK_LEN == SEED_LEN + FAKE_LEN + PK_LEN);
    assert!(ROUNDS >= 16 && ROUNDS <= 256);
    assert!(POLY_N * MOD_Q_BITS / 8 == POLY_PACKED_LEN);
    assert!(POLY_N * C1_Q_BITS / 8 == C1_PACKED_LEN);
    assert!(POLY_N * C2_Q_BITS / 8 == C2_PACKED_LEN);
    assert!(POLY_N * MSG_BITS_PER_COEFF / 8 == MSG_LEN);
    assert!(POLY_N * 4 / 8 == CBD_RAND_LEN);
};
