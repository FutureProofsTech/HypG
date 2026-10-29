//! FORS few-time signatures (`k = 35` trees, height `a = 9`).
//!
//! Secret leaf `(tree, leaf)`: `PRF(pubseed, esk, FORS addr)`.
//! Signature per tree: secret leaf + 9-node auth path. Public key:
//! Keyed-BLAKE3 over the 35 tree roots (all public geometry).

use crate::addr::{Addr, T_FORS, T_TREE};
use crate::params::{FORS_A, FORS_K, FORS_T, FORS_T_MASK, N};
use crate::thash::{h, prf};

/// FORS signature: per tree `(secret leaf, auth path)`.
pub type ForsSig = [([u8; N], [[u8; N]; FORS_A]); FORS_K];

/// FORS secret leaf value.
fn leaf_secret(pubseed: &[u8; N], esk: &[u8; N], tree: u32, leaf: u32) -> [u8; N] {
    let mut a = Addr::zero();
    a.set_type(T_FORS);
    a.set_f20(tree);
    a.set_f24(leaf);
    prf(pubseed, esk, &a)
}

/// FORS tree root for tree `t` (full 512-leaf build).
#[allow(clippy::many_single_char_names)]
fn tree_root(pubseed: &[u8; N], esk: &[u8; N], t: u32) -> [u8; N] {
    let mut level = [[0u8; N]; FORS_T];
    let mut l = 0u32;
    while (l as usize) < FORS_T {
        level[l as usize] = leaf_secret(pubseed, esk, t, l);
        l += 1;
    }
    let mut width = FORS_T;
    let mut height = 0u32;
    while width > 1 {
        let mut i = 0usize;
        let mut p = 0u32;
        while i < width {
            let mut a = Addr::zero();
            a.set_type(T_TREE);
            a.set_f20(t);
            a.set_f24(height);
            a.set_f28(p);
            level[i / 2] = h(pubseed, &a, &level[i], &level[i + 1]);
            p += 1;
            i += 2;
        }
        width /= 2;
        height += 1;
    }
    level[0]
}

/// FORS public key from secret: keyed hash over the `FORS_K` tree roots.
#[must_use]
pub fn fors_pk(pubseed: &[u8; N], esk: &[u8; N]) -> [u8; N] {
    let mut roots = [[0u8; N]; FORS_K];
    let mut t = 0u32;
    while (t as usize) < FORS_K {
        roots[t as usize] = tree_root(pubseed, esk, t);
        t += 1;
    }
    compress_roots(pubseed, &roots)
}

/// Compress `FORS_K` roots with the FORS-roots tweak: keyed hash over
/// `addr || roots` (`N + FORS_K * N` B, single chunk — one compression).
fn compress_roots(pubseed: &[u8; N], roots: &[[u8; N]; FORS_K]) -> [u8; N] {
    let mut a = Addr::zero();
    a.set_type(T_FORS);
    a.set_f20(0xFFFF_FFFF);
    let mut buf = [0u8; N + FORS_K * N];
    let mut o = 0usize;
    let mut i = 0usize;
    while i < N {
        buf[o] = a.0[i];
        o += 1;
        i += 1;
    }
    let mut t = 0usize;
    while t < FORS_K {
        i = 0;
        while i < N {
            buf[o] = roots[t][i];
            o += 1;
            i += 1;
        }
        t += 1;
    }
    let mut out = [0u8; N];
    hypg_core::b3::b3_keyed(pubseed, &buf, &mut out);
    out
}

/// FORS signature: per tree `(secret leaf, auth path[9])`.
/// `indices[t]` is the 9-bit leaf selector (public after digest split,
/// but derived from the secret-bound message — treated uniformly).
#[allow(clippy::many_single_char_names)]
#[must_use]
pub fn fors_sign(pubseed: &[u8; N], esk: &[u8; N], indices: &[u32; FORS_K]) -> ForsSig {
    let mut sig: ForsSig = [([0u8; N], [[0u8; N]; FORS_A]); FORS_K];
    let mut t = 0u32;
    while (t as usize) < FORS_K {
        sig[t as usize] = fors_sign_one(pubseed, esk, t, indices[t as usize]);
        t += 1;
    }
    sig
}

/// Sign a single FORS tree: secret leaf at `idx` plus its auth path.
///
/// Parallel building block for threaded signers (`hypg-mt`): trees are
/// pure functions of `(pubseed, esk, t, idx)` and independent.
/// Byte-identical to the corresponding entry of [`fors_sign`].
#[allow(clippy::many_single_char_names)]
#[must_use]
pub fn fors_sign_one(
    pubseed: &[u8; N],
    esk: &[u8; N],
    t: u32,
    idx: u32,
) -> ([u8; N], [[u8; N]; FORS_A]) {
    // Full tree (128 leaves) — simple and stack-resident.
    let mut level = [[0u8; N]; FORS_T];
    let mut l = 0u32;
    while (l as usize) < FORS_T {
        level[l as usize] = leaf_secret(pubseed, esk, t, l);
        l += 1;
    }
    let leaf = (idx & FORS_T_MASK) as usize;
    let mut unit = ([0u8; N], [[0u8; N]; FORS_A]);
    unit.0 = level[leaf];
    // Auth path with sibling subtree recompute (public indices).
    let mut work = level;
    let mut node = leaf;
    let mut width = FORS_T;
    let mut height = 0u32;
    while width > 1 {
        let sib = if node % 2 == 0 { node + 1 } else { node - 1 };
        unit.1[height as usize] = work[sib];
        let mut i = 0usize;
        let mut p = 0u32;
        while i < width {
            let mut a = Addr::zero();
            a.set_type(T_TREE);
            a.set_f20(t);
            a.set_f24(height);
            a.set_f28(p);
            work[i / 2] = h(pubseed, &a, &work[i], &work[i + 1]);
            p += 1;
            i += 2;
        }
        node /= 2;
        width /= 2;
        height += 1;
    }
    unit
}

/// FORS verify: recompute each tree root from leaf + path, compress.
#[allow(clippy::many_single_char_names)]
#[must_use]
pub fn fors_verify(pubseed: &[u8; N], indices: &[u32; FORS_K], sig: &ForsSig) -> [u8; N] {
    let mut roots = [[0u8; N]; FORS_K];
    let mut t = 0u32;
    while (t as usize) < FORS_K {
        let leaf32 = indices[t as usize] & FORS_T_MASK;
        let mut node = sig[t as usize].0;
        let mut at = leaf32;
        let mut height = 0u32;
        while (height as usize) < FORS_A {
            let mut a = Addr::zero();
            a.set_type(T_TREE);
            a.set_f20(t);
            a.set_f24(height);
            a.set_f28(at / 2);
            if at % 2 == 0 {
                node = h(pubseed, &a, &node, &sig[t as usize].1[height as usize]);
            } else {
                node = h(pubseed, &a, &sig[t as usize].1[height as usize], &node);
            }
            at /= 2;
            height += 1;
        }
        roots[t as usize] = node;
        t += 1;
    }
    compress_roots(pubseed, &roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fors_round_trip() {
        let ps = [0x61u8; N];
        let esk = [0x62u8; N];
        let mut idx = [0u32; FORS_K];
        let mut t = 0u32;
        while (t as usize) < FORS_K {
            idx[t as usize] = (t * 37 + 11) & FORS_T_MASK;
            t += 1;
        }
        let sig = fors_sign(&ps, &esk, &idx);
        assert_eq!(fors_verify(&ps, &idx, &sig), fors_pk(&ps, &esk));
        // Wrong index must not verify to the same key.
        let mut bad = idx;
        bad[0] ^= 1;
        assert_ne!(fors_verify(&ps, &bad, &sig), fors_pk(&ps, &esk));
    }
    #[test]
    fn sign_one_matches_batch() {
        // Per-tree units must equal the batch entries (parallel reliance).
        let ps = [0x61u8; N];
        let esk = [0x62u8; N];
        let mut idx = [0u32; FORS_K];
        let mut t = 0u32;
        while (t as usize) < FORS_K {
            idx[t as usize] = (t * 37 + 11) & FORS_T_MASK;
            t += 1;
        }
        let batch = fors_sign(&ps, &esk, &idx);
        let mut t = 0u32;
        while (t as usize) < FORS_K {
            assert_eq!(fors_sign_one(&ps, &esk, t, idx[t as usize]), batch[t as usize]);
            t += 1;
        }
    }

    #[test]
    fn leaf_boundaries_round_trip() {
        // Edge leaves `0` (all-left) and `511` (all-right): auth-path
        // sibling selection at the extremes, plus `sign_one`/batch
        // agreement there (the parallel driver signs edge trees too).
        let ps = [0x61u8; N];
        let esk = [0x62u8; N];
        for edge in [0u32, FORS_T_MASK] {
            let mut idx = [0u32; FORS_K];
            let mut t = 0u32;
            while (t as usize) < FORS_K {
                idx[t as usize] = (t * 37 + 11) & FORS_T_MASK;
                t += 1;
            }
            idx[0] = edge;
            let sig = fors_sign(&ps, &esk, &idx);
            assert_eq!(fors_verify(&ps, &idx, &sig), fors_pk(&ps, &esk), "edge {edge}");
            assert_eq!(fors_sign_one(&ps, &esk, 0, edge), sig[0]);
            // Off-by-one index must not verify.
            let mut bad = idx;
            bad[0] = if edge == 0 { 1 } else { FORS_T_MASK - 1 };
            assert_ne!(fors_verify(&ps, &bad, &sig), fors_pk(&ps, &esk));
        }
    }
}
