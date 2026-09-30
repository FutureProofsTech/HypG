//! DS parameters (`HypG-DS-128s` primary; `128f` reserved for later).
//!
//! All sizes fixed at compile time. `SIG_LEN` is large by nature
//! (hash-based signatures trade size for conservative assumptions).

/// Hash output / security parameter `n = 32` (BLAKE3-256, no truncation).
pub const N: usize = 32;
/// Hypertree total height `h = 60`.
pub const H: usize = 60;
/// Hypertree layers `d = 12`.
pub const D: usize = 12;
/// Per-layer XMSS height `h' = 5` (32 leaves per tree).
pub const HP: usize = 5;
/// Leaves per XMSS tree.
pub const LEAVES: usize = 32;
/// FORS trees `k = 30`.
pub const FORS_K: usize = 30;
/// FORS tree height `a = 7` (`t = 128` leaves).
pub const FORS_A: usize = 7;
/// FORS leaves per tree.
pub const FORS_T: usize = 128;
/// WOTS+ Winternitz parameter `w = 16`.
pub const W: usize = 16;
/// WOTS+ chain length counts: message digits, checksum digits, total.
pub const WOTS_LEN1: usize = 64;
/// Checksum digits.
pub const WOTS_LEN2: usize = 3;
/// Total WOTS+ chains.
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
/// Public key length: `root(32) || pubseed(32)`.
pub const SIG_PK_LEN: usize = 64;
/// Secret key length: `esk(32) || prf(32) || pubseed(32) || root(32)`.
pub const SIG_SK_LEN: usize = 128;
/// FORS signature length: `k·(a+1)·n`.
pub const FORS_SIG_LEN: usize = FORS_K * (FORS_A + 1) * N;
/// WOTS+ signature length: `len·n`.
pub const WOTS_SIG_LEN: usize = WOTS_LEN * N;
/// XMSS layer signature length: `idx(8) + WOTS + auth path (h'·n)`.
pub const XMSS_SIG_LEN: usize = 8 + WOTS_SIG_LEN + HP * N;
/// Full signature: `R(32) + FORS + d·XMSS`.
pub const SIG_LEN: usize = N + FORS_SIG_LEN + D * XMSS_SIG_LEN;

// Compile-time guards.
const _: () = {
    assert!(WOTS_LEN1 + WOTS_LEN2 == WOTS_LEN);
    assert!(D * HP == H);
    assert!(SIG_LEN == 35456);
    assert!(SIG_PK_LEN == 64);
    assert!(SIG_SK_LEN == 128);
};
