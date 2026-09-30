//! WOTS+ one-time signatures (`w = 16`, `len = 67`).
//!
//! Binding constant-time rule (see `docs/spec-ds.md` §4): chain positions
//! depend on secret message digits, so every chain executes all `w − 1`
//! steps and selects via branchless `ct_select`. Verification uses the
//! same routine (public inputs — identical code path, no separate logic).

use hypg_core::ct::ct_select;

use crate::addr::{Addr, T_WOTS_HASH, T_WOTS_PK};
use crate::params::{N, WOTS_LEN, WOTS_LEN1};
use crate::thash::{f, h, prf};

/// Chain from `x` over [`start`, `start` + `steps`), always executing all
/// 15 steps. `addr` must carry chain/hash fields; they are advanced
/// internally per step (public counters).
#[must_use]
pub fn chain(pubseed: &[u8; N], x: &[u8; N], start: u32, steps: u32, addr: &Addr) -> [u8; N] {
    let mut cur = *x;
    let mut out = *x;
    let mut s = 0u32;
    while s < 15 {
        let mut step_addr = *addr;
        step_addr.set_f28(start.wrapping_add(s));
        let h = f(pubseed, &step_addr, &cur);
        cur = h;
        // Branchless: take loop iteration `s` iff it lies inside the
        // requested segment (`s` counts from the segment start; the tweak
        // above carries the absolute position).
        let take = u8::from(s < steps);
        let mut sel = [0u8; N];
        ct_select(&mut sel, &h, &out, take);
        out = sel;
        s += 1;
    }
    out
}

/// Base-16 digits of a 32-byte message plus 3-digit checksum → 67 digits.
#[must_use]
pub fn digits(msg: &[u8; N]) -> [u8; WOTS_LEN] {
    let mut out = [0u8; WOTS_LEN];
    let mut i = 0u32;
    while (i as usize) < WOTS_LEN1 {
        let byte = msg[(i / 2) as usize];
        let shift = (i % 2) * 4;
        out[i as usize] = (byte >> shift) & 0x0F;
        i += 1;
    }
    let mut csum: u32 = 0;
    i = 0;
    while (i as usize) < WOTS_LEN1 {
        csum += 15 - u32::from(out[i as usize]);
        i += 1;
    }
    // `csum ≤ 64·15 = 960 < 4096`: 3 base-16 digits, big-endian.
    // (`try_from` targets always fit; the fallback is unreachable.)
    out[WOTS_LEN1] = u8::try_from((csum >> 8) & 0x0F).unwrap_or(0);
    out[WOTS_LEN1 + 1] = u8::try_from((csum >> 4) & 0x0F).unwrap_or(0);
    out[WOTS_LEN1 + 2] = u8::try_from(csum & 0x0F).unwrap_or(0);
    out
}

/// WOTS+ secret chain starts: `sk[i] = PRF(pubseed, esk, addr(chain=i))`.
#[must_use]
pub fn gen_sk(pubseed: &[u8; N], esk: &[u8; N], base: &Addr) -> [[u8; N]; WOTS_LEN] {
    let mut sk = [[0u8; N]; WOTS_LEN];
    let mut i = 0u32;
    while (i as usize) < WOTS_LEN {
        let mut a = *base;
        a.set_type(T_WOTS_HASH);
        a.set_f24(i);
        sk[i as usize] = prf(pubseed, esk, &a);
        i += 1;
    }
    sk
}

/// Sign message digits (secret-dependent → always-15 chains inside).
#[must_use]
pub fn sign(
    pubseed: &[u8; N],
    sk: &[[u8; N]; WOTS_LEN],
    msg_digits: &[u8; WOTS_LEN],
    base: &Addr,
) -> [[u8; N]; WOTS_LEN] {
    let mut sig = [[0u8; N]; WOTS_LEN];
    let mut i = 0u32;
    while (i as usize) < WOTS_LEN {
        let mut a = *base;
        a.set_type(T_WOTS_HASH);
        a.set_f24(i);
        sig[i as usize] = chain(pubseed, &sk[i as usize], 0, u32::from(msg_digits[i as usize]), &a);
        i += 1;
    }
    sig
}

/// Recover the WOTS+ public key from a signature (used in verify and
/// in public-key computation from a signature).
#[must_use]
pub fn pk_from_sig(
    pubseed: &[u8; N],
    sig: &[[u8; N]; WOTS_LEN],
    msg_digits: &[u8; WOTS_LEN],
    base: &Addr,
) -> [[u8; N]; WOTS_LEN] {
    let mut pk = [[0u8; N]; WOTS_LEN];
    let mut i = 0u32;
    while (i as usize) < WOTS_LEN {
        let mut a = *base;
        a.set_type(T_WOTS_HASH);
        a.set_f24(i);
        let d = u32::from(msg_digits[i as usize]);
        pk[i as usize] = chain(pubseed, &sig[i as usize], d, 15 - d, &a);
        i += 1;
    }
    pk
}

/// Full public key from secret (signing-time path).
#[must_use]
pub fn pk_from_sk(pubseed: &[u8; N], sk: &[[u8; N]; WOTS_LEN], base: &Addr) -> [[u8; N]; WOTS_LEN] {
    let mut pk = [[0u8; N]; WOTS_LEN];
    let mut i = 0u32;
    while (i as usize) < WOTS_LEN {
        let mut a = *base;
        a.set_type(T_WOTS_HASH);
        a.set_f24(i);
        pk[i as usize] = chain(pubseed, &sk[i as usize], 0, 15, &a);
        i += 1;
    }
    pk
}

/// L-tree compress 67 chain ends into one 32-byte node.
#[must_use]
pub fn ltree(pubseed: &[u8; N], leaves: &[[u8; N]; WOTS_LEN], base: &Addr) -> [u8; N] {
    // Pairwise hashing, duplicating the last node on odd levels (public geometry).
    let mut level = [[0u8; N]; WOTS_LEN];
    level.copy_from_slice(leaves);
    let mut width = WOTS_LEN;
    let mut height = 0u32;
    while width > 1 {
        let mut next = [[0u8; N]; 34];
        let mut p = 0u32;
        let mut i = 0usize;
        while i < width {
            let left = level[i];
            let right = if i + 1 < width { level[i + 1] } else { level[i] };
            let mut a = *base;
            a.set_type(T_WOTS_PK);
            a.set_f24(height);
            a.set_f28(p);
            next[p as usize] = h(pubseed, &a, &left, &right);
            p += 1;
            i += 2;
        }
        let mut j = 0usize;
        while j < (width + 1) / 2 {
            level[j] = next[j];
            j += 1;
        }
        width = (width + 1) / 2;
        height += 1;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_positions() {
        let ps = [0x11u8; N];
        let x = [0x22u8; N];
        let a = Addr::zero();
        // chain(0,15) == chain(0,5) then chain(5,10).
        let full = chain(&ps, &x, 0, 15, &a);
        let mid = chain(&ps, &x, 0, 5, &a);
        let cont = chain(&ps, &mid, 5, 10, &a);
        assert_eq!(full, cont);
        // Zero steps is identity.
        assert_eq!(chain(&ps, &x, 7, 0, &a), x);
    }
    #[test]
    fn wots_round_trip() {
        let ps = [0x33u8; N];
        let esk = [0x44u8; N];
        let base = Addr::zero();
        let sk = gen_sk(&ps, &esk, &base);
        let msg = [0xABu8; N];
        let d = digits(&msg);
        let sig = sign(&ps, &sk, &d, &base);
        let pk1 = pk_from_sig(&ps, &sig, &d, &base);
        let pk2 = pk_from_sk(&ps, &sk, &base);
        assert_eq!(pk1, pk2);
        assert_eq!(ltree(&ps, &pk1, &base), ltree(&ps, &pk2, &base));
    }

    #[test]
    fn checksum_extremes() {
        // All-zero message → max checksum `64·15 = 960 = 0x3C0`.
        let d0 = digits(&[0x00u8; N]);
        assert_eq!(&d0[WOTS_LEN1..], &[3u8, 12, 0]);
        // All-ones message → zero checksum.
        let dff = digits(&[0xFFu8; N]);
        assert_eq!(&dff[WOTS_LEN1..], &[0u8, 0, 0]);
        // Every digit is a nibble for all 256 uniform byte values
        // (encoder invariant the chains rely on: `digit ≤ 15`).
        let mut b = 0u32;
        while b < 256 {
            let byte = u8::try_from(b).unwrap_or(0);
            let d = digits(&[byte; N]);
            let mut i = 0usize;
            while i < WOTS_LEN {
                assert!(d[i] < 16, "non-nibble digit for byte {byte:#04x}");
                i += 1;
            }
            b += 1;
        }
    }
}
