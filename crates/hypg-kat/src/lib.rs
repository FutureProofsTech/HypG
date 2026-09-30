//! `HypG` KAT harness (std allowed here; libraries stay `no_std`).

use std::fmt::Write as _;

use hypg_core::b3::b3_hash;
use hypg_ds::{ds_keygen, ds_sign, ds_verify, SIG_LEN};
use hypg_hash::{
    derive32, hash32, hash64, keyed32, DIGEST32_LEN, DIGEST64_LEN, KEY_LEN as HASH_KEY_LEN,
};
use hypg_kem::{decaps, encaps, keygen};
use hypg_symm::{open, seal, Key, Nonce, TAG_LEN};

/// Frozen KAT vector file for the current spec version.
/// Compared byte-for-byte by `kats_match_frozen_file`.
pub const FROZEN_KATS: &str = include_str!("../kats/v0.7.0.txt");

/// Frozen hash-pillar KAT vector file (v0.7 hash/XOF/keyed/KDF vectors).
/// Compared byte-for-byte by `hash_kats_match_frozen_file`.
pub const FROZEN_HASH_KATS: &str = include_str!("../kats-hash/v0.7.0.txt");

/// Frozen Symm KAT vector file (v0.5 AEAD vectors).
/// Compared byte-for-byte by `symm_kats_match_frozen_file`.
pub const FROZEN_SYMM_KATS: &str = include_str!("../kats-symm/v0.7.0.txt");

/// Frozen DS KAT vector file (v0.6 signature vectors).
/// Compared byte-for-byte by `ds_kats_match_frozen_file`.
pub const FROZEN_DS_KATS: &str = include_str!("../kats-ds/v0.7.0.txt");

fn hex(bytes: &[u8], out: &mut String) {
    const H: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 2);
    for &b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0xf) as usize] as char);
    }
}

/// Render deterministic vectors (stable order, no RNG) for freezing
/// and cross-arch comparison.
///
/// # Example
///
/// ```rust
/// let kats = hypg_kat::render_kats();
/// assert!(kats.contains("hypg_version = 0.7.0"));
/// ```
///
/// # Panics
///
/// Panics if the internal round-trip invariant fails (indicates an
/// implementation bug, never bad input — inputs are fixed).
#[must_use]
pub fn render_kats() -> String {
    let mut s = String::new();
    // BLAKE3 sanity anchor (official vector for "abc").
    let mut h = [0u8; 32];
    b3_hash(b"abc", &mut h);
    s.push_str("b3_abc = ");
    hex(&h, &mut s);
    s.push_str("\nhypg_version = 0.7.0-module-n256-k2-q4096-b3\n");

    for tag in [0x00u8, 0x42u8, 0xFFu8] {
        let seed = [tag; 32];
        let coins = [(tag ^ 0x5A); 32];
        let (pk, sk) = keygen(&seed);
        let (ct, ss) = encaps(&pk, &coins);
        let ss2 = decaps(&sk, &ct);
        assert_eq!(ss, ss2, "round-trip must hold for KAT tag {tag:#04x}");
        let _ = write!(s, "--- tag {tag:#04x} ---\nseed = ");
        hex(&seed, &mut s);
        s.push_str("\npk   = ");
        hex(&pk.0, &mut s);
        s.push_str("\nsk   = ");
        hex(&sk.0, &mut s);
        s.push_str("\nct   = ");
        hex(&ct.0, &mut s);
        s.push_str("\nss   = ");
        hex(&ss.0, &mut s);
        s.push('\n');
    }
    s
}

/// Emit deterministic vectors to stdout (stable order, no RNG).
///
/// # Panics
///
/// Panics if the internal round-trip invariant fails (indicates an
/// implementation bug, never bad input — inputs are fixed).
pub fn print_kats() {
    print!("{}", render_kats());
}

/// Render deterministic Symm vectors (fixed key/nonce/message/AD cases).
///
/// # Example
///
/// ```rust
/// let kats = hypg_kat::render_symm_kats();
/// assert!(kats.contains("hypg_symm_version = 0.7.0"));
/// ```
///
/// # Panics
///
/// Panics if the internal round-trip invariant fails.
#[must_use]
pub fn render_symm_kats() -> String {
    let mut s = String::new();
    s.push_str("hypg_symm_version = 0.7.0-chacha-etm-b3mac\n");
    // (pt_len, ad_len, key_byte, nonce_byte) cases incl. rate edges.
    let cases: [(usize, usize, u8, u8); 5] = [
        (0, 0, 0x42, 0x11),
        (1, 1, 0x00, 0xFF),
        (127, 128, 0xA5, 0x5A),
        (128, 0, 0xFF, 0x00),
        (1000, 1000, 0x33, 0x77),
    ];
    for (idx, (pt_len, ad_len, kb, nb)) in cases.iter().enumerate() {
        let key = Key([*kb; 32]);
        let nonce = Nonce([*nb; 12]);
        let mut pt = [0u8; 1000];
        let mut ad = [0u8; 1000];
        let mut i = 0u32;
        let want_pt = u32::try_from(*pt_len).unwrap_or(0);
        while i < want_pt {
            let b = u8::try_from(i).unwrap_or(0xFF);
            pt[i as usize] = b.wrapping_mul(0x1F).wrapping_add(7);
            i += 1;
        }
        i = 0;
        let want_ad = u32::try_from(*ad_len).unwrap_or(0);
        while i < want_ad {
            let b = u8::try_from(i).unwrap_or(0xFF);
            ad[i as usize] = b.wrapping_mul(0x3B).wrapping_add(1);
            i += 1;
        }
        let (pt, ad) = (&pt[..*pt_len], &ad[..*ad_len]);
        let mut ct = [0u8; 1000];
        let mut back = [0u8; 1000];
        let (ct, back) = (&mut ct[..*pt_len], &mut back[..*pt_len]);
        let mut tag = [0u8; TAG_LEN];
        assert!(seal(&key, &nonce, ad, pt, ct, &mut tag).is_some());
        assert!(open(&key, &nonce, ad, ct, &tag, back).is_some());
        assert_eq!(back, pt, "symm round-trip failed for case {idx}");
        let _ = write!(s, "--- symm case {idx} pt_len={pt_len} ad_len={ad_len} ---\nkey = ");
        hex(&key.0, &mut s);
        s.push_str("\nnonce = ");
        hex(&nonce.0, &mut s);
        s.push_str("\nct = ");
        hex(ct, &mut s);
        s.push_str("\ntag = ");
        hex(&tag, &mut s);
        s.push('\n');
    }
    s
}

/// Emit deterministic Symm vectors to stdout.
///
/// # Panics
///
/// Panics if the internal round-trip invariant fails.
pub fn print_symm_kats() {
    print!("{}", render_symm_kats());
}

/// Render deterministic DS vectors (fixed seeds/messages; 35 KB sigs).
///
/// # Panics
///
/// Panics if sign/verify fails (implementation bug, never bad input).
#[must_use]
pub fn render_ds_kats() -> String {
    let mut s = String::new();
    s.push_str("hypg_ds_version = 0.7.0-slh-128s-n32-b3\n");
    let seeds: [[u8; 32]; 2] = [[0x42u8; 32], [0xFFu8; 32]];
    let msgs: [&[u8]; 2] = [b"", b"The quick brown fox jumps over the lazy dog. 0123456789"];
    for (idx, seed) in seeds.iter().enumerate() {
        let (pk, sk) = ds_keygen(seed);
        let msg = msgs[idx];
        #[allow(clippy::large_stack_arrays)]
        let mut sig = Box::new([0u8; SIG_LEN]); // heap-boxed immediately; libs keep stack discipline
        ds_sign(&sk, msg, &mut sig);
        assert!(ds_verify(&pk, msg, &sig[..]), "ds round-trip failed for case {idx}");
        let _ = write!(s, "--- ds case {idx} msg_len={} ---\nseed = ", msg.len());
        hex(seed, &mut s);
        s.push_str("\npk = ");
        hex(&pk.0, &mut s);
        s.push_str("\nsk = ");
        hex(&sk.0, &mut s);
        s.push_str("\nsig = ");
        hex(&sig[..], &mut s);
        s.push('\n');
    }
    s
}

/// Emit deterministic DS vectors to stdout.
///
/// # Panics
///
/// Panics if sign/verify fails.
pub fn print_ds_kats() {
    print!("{}", render_ds_kats());
}

/// Render deterministic hash-pillar vectors: `hash32`/`hash64` over
/// empty, short, and multi-chunk inputs plus keyed and derivation
/// samples (all through the `hypg-hash` API).
///
/// # Example
///
/// ```rust
/// let kats = hypg_kat::render_hash_kats();
/// assert!(kats.contains("hypg_hash_version = 0.7.0"));
/// ```
///
/// # Panics
///
/// Panics if the XOF-prefix invariant fails (implementation bug).
#[must_use]
pub fn render_hash_kats() -> String {
    let mut s = String::new();
    s.push_str("hypg_hash_version = 0.7.0-b3-api\n");
    let mut pattern = [0u8; 1025];
    let mut i = 0u32;
    while i < 1025 {
        pattern[i as usize] = u8::try_from(i.wrapping_mul(0x1F).wrapping_add(7)).unwrap_or(0);
        i += 1;
    }
    let inputs: [(&str, &[u8]); 3] = [("empty", b""), ("abc", b"abc"), ("pattern1025", &pattern)];
    for (idx, (name, input)) in inputs.iter().enumerate() {
        let mut h32 = [0u8; DIGEST32_LEN];
        let mut h64 = [0u8; DIGEST64_LEN];
        hash32(input, &mut h32);
        hash64(input, &mut h64);
        assert_eq!(&h64[..DIGEST32_LEN], &h32[..], "xof prefix must hold for {name}");
        let _ = write!(s, "--- hash case {idx} {name} len={} ---\nhash32 = ", input.len());
        hex(&h32, &mut s);
        s.push_str("\nhash64 = ");
        hex(&h64, &mut s);
        s.push('\n');
    }
    let mut mac = [0u8; DIGEST32_LEN];
    keyed32(&[0x42u8; HASH_KEY_LEN], b"abc", &mut mac);
    s.push_str("keyed32 = ");
    hex(&mac, &mut s);
    let mut dk = [0u8; DIGEST32_LEN];
    derive32("HYP-G/v07/kat", &[0x42u8; HASH_KEY_LEN], &mut dk);
    s.push_str("\nderive32 = ");
    hex(&dk, &mut s);
    s.push('\n');
    s
}

/// Emit deterministic hash-pillar vectors to stdout.
///
/// # Panics
///
/// Panics if the XOF-prefix invariant fails.
pub fn print_hash_kats() {
    print!("{}", render_hash_kats());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kats_round_trip() {
        for tag in [0x00u8, 0x01u8, 0x42u8, 0xA5u8, 0xFFu8] {
            let seed = [tag; 32];
            let coins = [tag.wrapping_add(0x33); 32];
            let (pk, sk) = keygen(&seed);
            let (ct, ss1) = encaps(&pk, &coins);
            let ss2 = decaps(&sk, &ct);
            assert_eq!(ss1, ss2);
            assert_eq!(pk.0.len(), 800);
            assert_eq!(ct.0.len(), 800);
        }
    }

    #[test]
    fn kats_match_frozen_file() {
        assert_eq!(
            render_kats(),
            FROZEN_KATS,
            "KAT output drifted from crates/hypg-kat/kats/v0.4.0.txt; \
             any intentional vector change requires a spec version bump \
             and a newly frozen file"
        );
    }

    #[test]
    fn symm_kats_match_frozen_file() {
        assert_eq!(
            render_symm_kats(),
            FROZEN_SYMM_KATS,
            "Symm KAT output drifted from crates/hypg-kat/kats-symm/v0.5.0.txt; \
             any intentional vector change requires a spec version bump \
             and a newly frozen file"
        );
    }

    #[test]
    fn ds_kats_match_frozen_file() {
        assert_eq!(
            render_ds_kats(),
            FROZEN_DS_KATS,
            "DS KAT output drifted from crates/hypg-kat/kats-ds/v0.6.0.txt; \
             any intentional vector change requires a spec version bump \
             and a newly frozen file"
        );
    }

    #[test]
    fn hash_kats_match_frozen_file() {
        assert_eq!(
            render_hash_kats(),
            FROZEN_HASH_KATS,
            "Hash KAT output drifted from crates/hypg-kat/kats-hash/v0.7.0.txt; \
             any intentional vector change requires a spec version bump \
             and a newly frozen file"
        );
    }
}
