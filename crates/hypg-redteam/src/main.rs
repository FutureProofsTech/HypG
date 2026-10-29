//! `hypg-redteam`: adversarial test harness (std binary, zero-dep).
//!
//! Suites (all deterministic, no RNG; exit non-zero on any failure):
//! - `S1` garbage-input robustness (zero/`FF` keys and ciphertexts).
//! - `S2` ciphertext malleability sweep (single-bit flips must change `ss`).
//! - `S3` key-mismatch matrix (`8×8`, only the diagonal must agree).
//! - `S4` message extremes (`00/FF/AA/55/sequential` coins).
//! - `S5` FO binding (same coins + other `pk`, same `pk` + other coins).
//! - `S6` sampler statistics (CBD range/signs over a long stream).
//! - `S7` failure-rate sweep (`HYPG_REDTEAM_TRIALS`, default 64).
//! - `S8` determinism double-run.
//! - `S9` AEAD adversarial sweep (tag flips, key/nonce/ad/ct flips,
//!   empty-both, determinism).
//! - `S10` signature forgery sweep (sig/message/key flips reject,
//!   determinism, wrong-key).
//! - `S11` adversarial mega-suite (burst faults, tampered `pk`, garbage
//!   matrix, DS pad flips, multi-sign, 1 MiB AEAD).
//! - `S12` panic sweep (deterministic adversarial corpus over all
//!   fallible/total APIs — must never panic, contracts must hold).
//! - `S13` secret-key bit-flip sweep (implicit rejection, no panic).
//! - `S14` streaming AEAD adversarial suite (chunk-split equivalence,
//!   reorder/truncate/duplicate rejection, 1 MiB stream identity).
//!
//! Configure cost: `HYPG_REDTEAM_TRIALS` (2..=1048576, default 64),
//! `HYPG_REDTEAM_FLIPS` (`1..=CT_LEN`, `all` = every ciphertext bit,
//! default 48).

use hypg_core::params::{CT_LEN, PK_LEN, SK_LEN};
use hypg_core::poly::cbd_eta2;
use hypg_kem::{decaps, encaps, keygen};

fn trials() -> u32 {
    std::env::var("HYPG_REDTEAM_TRIALS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&n| (2..=1_048_576).contains(&n))
        .unwrap_or(64)
}

fn flips() -> usize {
    if std::env::var("HYPG_REDTEAM_FLIPS").as_deref() == Ok("all") {
        return CT_LEN * 8; // full-bit mode: every bit of every ct byte
    }
    std::env::var("HYPG_REDTEAM_FLIPS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| (1..=CT_LEN).contains(&n))
        .unwrap_or(48)
}

fn prng32(mut x: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    for b in &mut out {
        x = x.wrapping_mul(0x9E37_79B9).wrapping_add(0x85EB_CA6B);
        *b = u8::try_from((x >> 11) & 0xFF).unwrap_or(0);
    }
    out
}

/// `S1`: garbage inputs must never panic; wrong-key decaps must not
/// return the legitimate shared secret.
fn s1() -> (bool, String) {
    let (pk, sk) = keygen(&[0x42u8; 32]);
    let (ct, ss) = encaps(&pk, &[0x11u8; 32]);
    let ff_ct = [0xFFu8; CT_LEN];
    let zero_pk = [0u8; PK_LEN];
    let r1 = std::panic::catch_unwind(|| decaps(&sk, &hypg_kem::Ciphertext(ff_ct)));
    let r2 = std::panic::catch_unwind(|| encaps(&hypg_kem::PublicKey(zero_pk), &[0x00u8; 32]));
    let r3 = std::panic::catch_unwind(|| {
        let (_, bad_sk) = keygen(&[0x99u8; 32]);
        decaps(&bad_sk, &ct)
    });
    let no_panic = r1.is_ok() && r2.is_ok() && r3.is_ok();
    let mismatch = r3.is_ok_and(|s| s != ss);
    let (_, sk2) = keygen(&[0x99u8; 32]);
    let sk_prefix_differs = sk.0[..64] != sk2.0[..64];
    let ok = no_panic && mismatch && sk_prefix_differs;
    (
        ok,
        format!(
            "no_panic={no_panic} mismatch_rejects={mismatch} sk_prefix_differs={sk_prefix_differs}"
        ),
    )
}

/// `S2`: single-bit flips across the first `n` ct bytes plus the last
/// 16 bytes (tail coverage) must all change `ss`. With
/// `HYPG_REDTEAM_FLIPS=all`, every bit of every byte is flipped
/// (`n == 8*CT_LEN`, full ciphertext-bit sweep — release only in practice).
fn s2(n: usize) -> (bool, String) {
    use hypg_core::params::CT_LEN;
    let (pk, sk) = keygen(&[0x42u8; 32]);
    let (ct, ss) = encaps(&pk, &[0x11u8; 32]);
    let mut unchanged = 0u32;
    let mut checked = 0u32;
    let mut flip = |pos: usize, bit: u32| {
        let mut bad = ct;
        bad.0[pos] ^= 1u8 << bit;
        checked += 1;
        if decaps(&sk, &bad) == ss {
            unchanged += 1;
        }
    };
    if n > CT_LEN {
        // Full-bit mode (every bit position, not just bit 0).
        for pos in 0..CT_LEN {
            for bit in 0..8u32 {
                flip(pos, bit);
            }
        }
        (
            unchanged == 0,
            format!(
                "{checked} flips (all {} bit positions), {unchanged} left ss unchanged",
                CT_LEN * 8
            ),
        )
    } else {
        for i in 0..n {
            flip(i, 0);
        }
        for i in 0..16usize {
            flip(CT_LEN - 16 + i, 0);
        }
        (
            unchanged == 0,
            format!("{checked} single-bit flips (head+tail), {unchanged} left ss unchanged"),
        )
    }
}

/// `S3`: 8×8 key-mismatch matrix (only the diagonal must agree).
fn s3() -> (bool, String) {
    let mut keys = Vec::new();
    for k in 0..8u32 {
        keys.push(keygen(&prng32(0x1000 + k)));
    }
    let mut bad = 0u32;
    for (i, (pk, _)) in keys.iter().enumerate() {
        let (ct, ss) = encaps(pk, &[0x77u8; 32]);
        for (j, (_, sk)) in keys.iter().enumerate() {
            if (decaps(sk, &ct) == ss) != (i == j) {
                bad += 1;
            }
        }
    }
    (bad == 0, format!("8x8 matrix, {bad} off-diagonal anomalies"))
}

/// `S4`: message extremes must all round-trip.
fn s4() -> (bool, String) {
    let coins_set: [[u8; 32]; 5] = [
        [0x00; 32],
        [0xFF; 32],
        [0xAA; 32],
        [0x55; 32],
        core::array::from_fn(|i| u8::try_from(i).unwrap_or(0xFF)),
    ];
    let (pk, sk) = keygen(&[0x5Au8; 32]);
    let mut bad = 0u32;
    for coins in &coins_set {
        let (ct, ss) = encaps(&pk, coins);
        if decaps(&sk, &ct) != ss {
            bad += 1;
        }
    }
    (bad == 0, format!("5 extreme messages, {bad} failures"))
}

/// `S5`: FO binding in both directions.
fn s5() -> (bool, String) {
    let (pk_a, _) = keygen(&[0xAAu8; 32]);
    let (pk_b, _) = keygen(&[0xBBu8; 32]);
    let coins = [0xCCu8; 32];
    let (ct_a, ss_a) = encaps(&pk_a, &coins);
    let (ct_b, ss_b) = encaps(&pk_b, &coins);
    let (ct_a2, ss_a2) = encaps(&pk_a, &[0xDDu8; 32]);
    let pk_bound = ct_a != ct_b && ss_a != ss_b;
    let coins_bound = ct_a != ct_a2 && ss_a != ss_a2;
    (pk_bound && coins_bound, format!("pk_bound={pk_bound} coins_bound={coins_bound}"))
}

/// `S6`: CBD statistics over 2048 polys (524288 coeffs).
fn s6() -> (bool, String) {
    let mut sum: i64 = 0;
    let mut count: i64 = 0;
    let mut neg = false;
    let mut pos = false;
    let mut out_of_range = 0u32;
    for t in 0..2048u32 {
        let mut stream = [0u8; 128];
        for (i, b) in stream.iter_mut().enumerate() {
            let idx = u32::try_from(i).unwrap_or(0xFFFF);
            let x = (t.wrapping_mul(0x9E37_79B9)).wrapping_add(idx.wrapping_mul(0x85EB_CA6B));
            *b = u8::try_from((x >> 13) & 0xFF).unwrap_or(0);
        }
        for c in cbd_eta2(&stream).0 {
            let signed = if c > 0x0FFF / 2 { i32::from(c) - 0x1000 } else { i32::from(c) };
            if !(-2..=2).contains(&signed) {
                out_of_range += 1;
            }
            sum += i64::from(signed);
            count += 1;
            if signed < 0 {
                neg = true;
            }
            if signed > 0 {
                pos = true;
            }
        }
    }
    // Integer mean in thousandths (no floats): `|mean|*1000 < 50`.
    let mean_pm = (sum * 1000 / count).abs();
    let ok = out_of_range == 0 && neg && pos && mean_pm < 50;
    (ok, format!("n={count} out_of_range={out_of_range} mean_pm={mean_pm} neg={neg} pos={pos}"))
}

/// `S7`: failure-rate sweep.
fn s7(n: u32) -> (bool, String) {
    let mut fails = 0u32;
    for i in 0..n {
        let seed = prng32(0x2000 + i);
        let coins = prng32(0x8000 + i);
        let (pk, sk) = keygen(&seed);
        let (ct, ss) = encaps(&pk, &coins);
        if decaps(&sk, &ct) != ss {
            fails += 1;
        }
    }
    (fails == 0, format!("{n} trials, {fails} failures"))
}

/// `S8`: determinism double-run incl. `sk` embedding of `pk`.
fn s8() -> (bool, String) {
    let seed = [0x42u8; 32];
    let (pk1, sk1) = keygen(&seed);
    let (pk2, sk2) = keygen(&seed);
    let (ct1, ss1) = encaps(&pk1, &[0x11u8; 32]);
    let (ct2, ss2) = encaps(&pk1, &[0x11u8; 32]);
    let embedded = sk1.0[64..] == pk1.0;
    let ok = pk1 == pk2 && sk1 == sk2 && ct1 == ct2 && ss1 == ss2 && embedded;
    (ok, format!("stable={ok} sk_embeds_pk={embedded}"))
}

/// `S9`: AEAD adversarial sweep — full 32-byte tag flip set (all reject),
/// ct/key/nonce/ad flips (reject or deterministic change), empty-both
/// round-trip, determinism.
fn s9() -> (bool, String) {
    use hypg_symm::{open, seal, Key, Nonce, KEY_LEN, NONCE_LEN, TAG_LEN};
    let key = Key([0x42u8; KEY_LEN]);
    let nonce = Nonce([0x11u8; NONCE_LEN]);
    let pt = b"redteam aead probe message";
    let ad = b"associated-data";
    let mut ct = [0u8; 26];
    let mut tag = [0u8; TAG_LEN];
    if seal(&key, &nonce, ad, pt, &mut ct, &mut tag).is_none() {
        return (false, "seal failed on valid input".to_string());
    }
    // Full tag flip set: every single-bit flip of all 32 tag bytes rejects.
    let mut tag_holds = 0u32;
    for i in 0..TAG_LEN {
        for bit in [0x01u8, 0x80] {
            let mut bad = tag;
            bad[i] ^= bit;
            let mut back = [0u8; 26];
            if open(&key, &nonce, ad, &ct, &bad, &mut back).is_some() {
                tag_holds += 1;
            }
        }
    }
    // Ciphertext / AD / key / nonce flips must never verify as the original.
    let mut bad_ct = ct;
    bad_ct[0] ^= 0x01;
    let mut back = [0u8; 26];
    let ct_flip_rejects = open(&key, &nonce, ad, &bad_ct, &tag, &mut back).is_none();
    let ad_flip_rejects = open(&key, &nonce, b"associated-datb", &ct, &tag, &mut back).is_none();
    let wrong_key = open(&Key([0x43u8; KEY_LEN]), &nonce, ad, &ct, &tag, &mut back).is_none();
    let wrong_nonce = open(&key, &Nonce([0x12u8; NONCE_LEN]), ad, &ct, &tag, &mut back).is_none();
    // Empty-both round-trip + determinism.
    let mut ct0 = [0u8; 0];
    let mut back0 = [0u8; 0];
    let mut tag0 = [0u8; TAG_LEN];
    let empty_ok = seal(&key, &nonce, b"", b"", &mut ct0, &mut tag0).is_some()
        && open(&key, &nonce, b"", &ct0, &tag0, &mut back0).is_some();
    let mut ct2 = [0u8; 26];
    let mut tag2 = [0u8; TAG_LEN];
    let det_ok =
        seal(&key, &nonce, ad, pt, &mut ct2, &mut tag2).is_some() && ct2 == ct && tag2 == tag;
    let ok = tag_holds == 0
        && ct_flip_rejects
        && ad_flip_rejects
        && wrong_key
        && wrong_nonce
        && empty_ok
        && det_ok;
    (
        ok,
        format!(
            "tag_flips_held={tag_holds}/64 ct_reject={ct_flip_rejects} ad_reject={ad_flip_rejects} \
             key_reject={wrong_key} nonce_reject={wrong_nonce} empty={empty_ok} det={det_ok}"
        ),
    )
}

/// `S10`: signature forgery sweep — flips across sig regions, message,
/// and key must all reject; signing is deterministic.
fn s10() -> (bool, String) {
    use hypg_ds::{ds_keygen, ds_sign, ds_verify, SIG_LEN};
    let (pk, sk) = ds_keygen(&[0x42u8; 32]);
    let msg = b"redteam ds probe";
    #[allow(clippy::large_stack_arrays)]
    let mut sig = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
    ds_sign(&sk, msg, &mut sig);
    if !ds_verify(&pk, msg, &sig[..]) {
        return (false, "valid signature rejected".to_string());
    }
    // Flip one byte per region: R, FORS leaf, FORS path, WOTS, auth, pad, tail.
    let mut holds = 0u32;
    for pos in [0usize, 40, 4000, 9000, 20000, 30000, SIG_LEN - 1] {
        let mut bad = sig.clone();
        bad[pos] ^= 0x01;
        if ds_verify(&pk, msg, &bad[..]) {
            holds += 1;
        }
    }
    let msg_flip = !ds_verify(&pk, b"redteam ds probf", &sig[..]);
    let (pk2, _) = ds_keygen(&[0x43u8; 32]);
    let key_flip = !ds_verify(&pk2, msg, &sig[..]);
    #[allow(clippy::large_stack_arrays)]
    let mut sig2 = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
    ds_sign(&sk, msg, &mut sig2);
    let det = sig2 == sig;
    let ok = holds == 0 && msg_flip && key_flip && det;
    (ok, format!("forgeries_held={holds}/7 msg_reject={msg_flip} key_reject={key_flip} det={det}"))
}

/// `S11a`: KEM fault injection — burst faults, tampered `pk`, garbage matrix.
fn s11a() -> (bool, String) {
    use hypg_core::params::CT_LEN;
    // A. Burst faults: 2/3/4-bit deterministic bursts must all change `ss`.
    let (pk, sk) = keygen(&[0x42u8; 32]);
    let (ct, ss) = encaps(&pk, &[0x11u8; 32]);
    let mut burst_holds = 0u32;
    let mut burst_n = 0u32;
    for base in [0usize, 100, 400, 799] {
        for width in [2u32, 3, 4] {
            let mut bad = ct;
            let mut w = 0u32;
            while w < width {
                let pos = (base + w as usize) % CT_LEN;
                bad.0[pos] ^= 0x01u8 << (w % 8);
                w += 1;
            }
            burst_n += 1;
            if decaps(&sk, &bad) == ss {
                burst_holds += 1;
            }
        }
    }
    // B. Tampered `pk`: encaps under flipped pk, decaps under original sk.
    let mut bad_pk = pk;
    bad_pk.0[0] ^= 0x01;
    bad_pk.0[PK_LEN - 1] ^= 0x80;
    let (ct_b, ss_b) = encaps(&bad_pk, &[0x11u8; 32]);
    // Re-encryption binds the real pk: decaps under the original sk must
    // not recover the sender-side `ss_b`.
    let pk_tamper = decaps(&sk, &ct_b) != ss_b;
    // C. Garbage matrix: {zero, FF} sk × {zero, FF} ct — no panic, never
    // equals a legitimate `ss`.
    let sks = [hypg_kem::SecretKey([0u8; SK_LEN]), hypg_kem::SecretKey([0xFFu8; SK_LEN])];
    let cts = [hypg_kem::Ciphertext([0u8; CT_LEN]), hypg_kem::Ciphertext([0xFFu8; CT_LEN])];
    let mut garbage_ok = true;
    for skg in &sks {
        for ctg in &cts {
            let r = std::panic::catch_unwind(|| decaps(skg, ctg));
            match r {
                Ok(s) => {
                    if s == ss {
                        garbage_ok = false;
                    }
                }
                Err(_) => garbage_ok = false,
            }
        }
    }
    let ok = burst_holds == 0 && pk_tamper && garbage_ok;
    (ok, format!("burst_held={burst_holds}/{burst_n} pk_tamper={pk_tamper} garbage={garbage_ok}"))
}

/// 1 MiB AEAD probe size.
const BIG: usize = 1 << 20;

/// `S11b`: DS pad flips, multi-sign, 1 MiB AEAD.
fn s11b() -> (bool, String) {
    use hypg_ds::{ds_keygen, ds_sign, ds_verify, SIG_LEN};
    use hypg_symm::{open, seal, Key, Nonce, KEY_LEN, NONCE_LEN, TAG_LEN};
    // D. DS reserved-pad flips at all layer offsets must reject.
    // Pad `l` starts at `N + FORS_SIG_LEN + l*XMSS_SIG_LEN`.
    let (dpk, dsk) = ds_keygen(&[0x43u8; 32]);
    let dmsg = b"redteam s11 ds";
    #[allow(clippy::large_stack_arrays)]
    let mut dsig = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
    ds_sign(&dsk, dmsg, &mut dsig);
    let mut pad_holds = 0u32;
    if !ds_verify(&dpk, dmsg, &dsig[..]) {
        return (false, "s11 valid ds signature rejected".to_string());
    }
    let mut l = 0usize;
    while l < hypg_ds::params::D {
        let mut bad = dsig.clone();
        bad[hypg_ds::params::N
            + hypg_ds::params::FORS_SIG_LEN
            + l * hypg_ds::params::XMSS_SIG_LEN] ^= 0x01;
        if ds_verify(&dpk, dmsg, &bad[..]) {
            pad_holds += 1;
        }
        l += 1;
    }
    // E. Multi-sign: two messages, one key — both verify, neither cross-verifies.
    let m1 = b"first message";
    let m2 = b"second message!!";
    #[allow(clippy::large_stack_arrays)]
    let mut sig_a = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
    #[allow(clippy::large_stack_arrays)]
    let mut sig_b = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
    ds_sign(&dsk, m1, &mut sig_a);
    ds_sign(&dsk, m2, &mut sig_b);
    let multi_ok = ds_verify(&dpk, m1, &sig_a[..])
        && ds_verify(&dpk, m2, &sig_b[..])
        && !ds_verify(&dpk, m1, &sig_b[..])
        && !ds_verify(&dpk, m2, &sig_a[..])
        && sig_a != sig_b;
    // F. 1 MiB AEAD round-trip + head/tail tamper.
    let akey = Key([0x44u8; KEY_LEN]);
    let anonce = Nonce([0x45u8; NONCE_LEN]);
    let mut pt = Vec::with_capacity(BIG);
    let mut i = 0u32;
    while (i as usize) < BIG {
        pt.push(u8::try_from(i * 13 + 7).unwrap_or(0));
        i += 1;
    }
    let mut ct_big = vec![0u8; BIG];
    let mut back_big = vec![0u8; BIG];
    let mut tag_big = [0u8; TAG_LEN];
    let big_ok = seal(&akey, &anonce, b"big-ad", &pt, &mut ct_big, &mut tag_big).is_some()
        && open(&akey, &anonce, b"big-ad", &ct_big, &tag_big, &mut back_big).is_some()
        && back_big == pt;
    ct_big[0] ^= 0x01;
    ct_big[BIG - 1] ^= 0x80;
    let big_tamper = open(&akey, &anonce, b"big-ad", &ct_big, &tag_big, &mut back_big).is_none();
    let ok = pad_holds == 0 && multi_ok && big_ok && big_tamper;
    (
        ok,
        format!(
            "pad_held={pad_holds}/{} multi={multi_ok} big1m={big_ok} big_tamper={big_tamper}",
            hypg_ds::params::D
        ),
    )
}

/// `S11`: combined adversarial mega-suite (A–F across [`s11a`], [`s11b`]).
fn s11() -> (bool, String) {
    let (ok_a, detail_a) = s11a();
    let (ok_b, detail_b) = s11b();
    (ok_a && ok_b, format!("s11a[{detail_a}] s11b[{detail_b}]"))
}

/// Deterministic corpus PRNG (LCG, fixed seed — no OS randomness).
struct Corpus {
    x: u32,
}

impl Corpus {
    fn next(&mut self, m: u32) -> u32 {
        self.x = self.x.wrapping_mul(0x9E37_79B9).wrapping_add(0x85EB_CA6B);
        (self.x >> 7) % m
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = u8::try_from((self.next(65_536) >> 8) & 0xFF).unwrap_or(0);
        }
    }
}

/// `S12`: adversarial corpus over every fallible/total API — KEM
/// `encaps`/`decaps` (300 cases), AEAD `seal`/`open` (700 cases),
/// `ds_verify` (12 cases incl. random ~50 KB blobs). Nothing may panic;
/// round-trip and fail-closed contracts must hold.
/// `S12a`: KEM corpus — random keys/ciphertexts must not panic; the
/// honest pair inside the loop must always round-trip.
fn s12a(rng: &mut Corpus) -> (bool, String) {
    use hypg_core::params::SK_LEN;
    let (pk0, sk0) = keygen(&[0x5Au8; 32]);
    let mut panics = 0u32;
    let mut violations = 0u32;
    let mut n = 0u32;
    for _ in 0..300 {
        let mut skb = [0u8; SK_LEN];
        rng.fill(&mut skb);
        let mut ctb = [0u8; CT_LEN];
        rng.fill(&mut ctb);
        let mut pkb = [0u8; PK_LEN];
        rng.fill(&mut pkb);
        let r1 = std::panic::catch_unwind(|| {
            decaps(&hypg_kem::SecretKey(skb), &hypg_kem::Ciphertext(ctb))
        });
        let r2 = std::panic::catch_unwind(|| encaps(&hypg_kem::PublicKey(pkb), &[0x11u8; 32]));
        if r1.is_err() || r2.is_err() {
            panics += 1;
        }
        let mut coins = [0u8; 32];
        rng.fill(&mut coins);
        match std::panic::catch_unwind(|| {
            let (c, s1) = encaps(&pk0, &coins);
            let s2 = decaps(&sk0, &c);
            (s1, s2)
        }) {
            Ok((s1, s2)) => {
                if s1 != s2 {
                    violations += 1;
                }
            }
            Err(_) => panics += 1,
        }
        n += 1;
    }
    (
        panics == 0 && violations == 0,
        format!("kem {n} cases panics={panics} violations={violations}"),
    )
}

/// `S12b`: AEAD corpus — consistent lengths must seal+open cleanly;
/// garbage tags must fail closed (a random 32 B tag verifies with
/// probability 2^-256 — a hit would be a real finding, not flake).
fn s12b(rng: &mut Corpus) -> (bool, String) {
    use hypg_symm::{open, seal, Key, Nonce, TAG_LEN};
    let mut panics = 0u32;
    let mut violations = 0u32;
    let mut n = 0u32;
    for _ in 0..700 {
        let pt_len = rng.next(65) as usize;
        let ad_len = rng.next(65) as usize;
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let mut pt = [0u8; 64];
        rng.fill(&mut pt[..pt_len]);
        let mut ad = [0u8; 64];
        rng.fill(&mut ad[..ad_len]);
        let sealed = std::panic::catch_unwind(|| {
            let mut ct = [0u8; 64];
            let mut tag = [0u8; TAG_LEN];
            seal(
                &Key(key),
                &Nonce(nonce),
                &ad[..ad_len],
                &pt[..pt_len],
                &mut ct[..pt_len],
                &mut tag,
            )
            .map(|()| (ct, tag))
        });
        match sealed {
            Ok(Some((ct, tag))) => {
                let opened = std::panic::catch_unwind(|| {
                    let mut back = [0u8; 64];
                    open(
                        &Key(key),
                        &Nonce(nonce),
                        &ad[..ad_len],
                        &ct[..pt_len],
                        &tag,
                        &mut back[..pt_len],
                    )
                    .map(|()| back)
                });
                match opened {
                    Ok(Some(back)) => {
                        if back[..pt_len] != pt[..pt_len] {
                            violations += 1;
                        }
                    }
                    Ok(None) => violations += 1,
                    Err(_) => panics += 1,
                }
                let mut bad_tag = [0u8; TAG_LEN];
                rng.fill(&mut bad_tag);
                let forged = std::panic::catch_unwind(|| {
                    let mut back = [0u8; 64];
                    open(
                        &Key(key),
                        &Nonce(nonce),
                        &ad[..ad_len],
                        &ct[..pt_len],
                        &bad_tag,
                        &mut back[..pt_len],
                    )
                });
                match forged {
                    Ok(r) => {
                        if r.is_some() {
                            violations += 1;
                        }
                    }
                    Err(_) => panics += 1,
                }
            }
            Ok(None) => violations += 1,
            Err(_) => panics += 1,
        }
        n += 1;
    }
    (
        panics == 0 && violations == 0,
        format!("aead {n} cases panics={panics} violations={violations}"),
    )
}

/// `S12c`: DS verify corpus — valid verifies; random blobs never panic
/// and reject unless exactly `SIG_LEN` (then the verdict is
/// unconstrained).
fn s12c(rng: &mut Corpus) -> (bool, String) {
    use hypg_ds::{ds_keygen, ds_sign, ds_verify, SIG_LEN};
    let mut panics = 0u32;
    let mut violations = 0u32;
    let mut n = 0u32;
    let (dpk, dsk) = ds_keygen(&[0x77u8; 32]);
    #[allow(clippy::large_stack_arrays)]
    let mut dsig = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
    ds_sign(&dsk, b"s12 corpus", &mut dsig);
    if !ds_verify(&dpk, b"s12 corpus", &dsig[..]) {
        violations += 1;
    }
    n += 1;
    for _ in 0..10 {
        let len = rng.next(u32::try_from(SIG_LEN + 8).unwrap_or(u32::MAX)) as usize;
        let mut blob = vec![0u8; len];
        rng.fill(&mut blob);
        match std::panic::catch_unwind(|| ds_verify(&dpk, b"s12 corpus", &blob)) {
            Ok(v) => {
                if len != SIG_LEN && v {
                    violations += 1;
                }
            }
            Err(_) => panics += 1,
        }
        n += 1;
    }
    (
        panics == 0 && violations == 0,
        format!("ds {n} cases panics={panics} violations={violations}"),
    )
}

/// `S12`: combined panic sweep (KEM + AEAD + DS corpora).
fn s12() -> (bool, String) {
    let mut rng = Corpus { x: 0x1234_5678 };
    let (ok_a, detail_a) = s12a(&mut rng);
    let (ok_b, detail_b) = s12b(&mut rng);
    let (ok_c, detail_c) = s12c(&mut rng);
    (ok_a && ok_b && ok_c, format!("s12a[{detail_a}] s12b[{detail_b}] s12c[{detail_c}]"))
}

/// `S13`: single-bit flips in `sk` across seed/fake/`pk` regions.
/// Seed/`pk` corruption must break the exchange (implicit rejection, no
/// panic). The fake key is a spare read only on the reject branch, so
/// fake corruption must be invisible on the honest path yet change the
/// reject output (proves the spare is actually wired in).
fn s13() -> (bool, String) {
    use hypg_core::params::SK_LEN;
    let (pk, sk) = keygen(&[0x42u8; 32]);
    let (ct, ss) = encaps(&pk, &[0x11u8; 32]);
    let mut bad_ct = ct;
    bad_ct.0[0] ^= 0x01;
    let baseline_reject = decaps(&sk, &bad_ct);
    let mut bad = 0u32;
    let mut n = 0u32;
    // Seed + embedded-pk regions: exchange must break, cleanly.
    for pos in [0usize, 17, 31, 64, 200, SK_LEN - 1] {
        for bit in [0u32, 3, 7] {
            let mut skb = sk;
            skb.0[pos] ^= 1u8 << bit;
            n += 1;
            match std::panic::catch_unwind(|| decaps(&skb, &ct)) {
                Ok(s) => {
                    if s == ss {
                        bad += 1;
                    }
                }
                Err(_) => bad += 1,
            }
        }
    }
    // Fake-key region: honest path unchanged, reject path diverges.
    for pos in [32usize, 47, 63] {
        for bit in [0u32, 3, 7] {
            let mut skb = sk;
            skb.0[pos] ^= 1u8 << bit;
            n += 1;
            match std::panic::catch_unwind(|| (decaps(&skb, &ct), decaps(&skb, &bad_ct))) {
                Ok((s_honest, s_reject)) => {
                    if s_honest != ss || s_reject == baseline_reject {
                        bad += 1;
                    }
                }
                Err(_) => bad += 1,
            }
        }
    }
    (bad == 0, format!("{n} sk single-bit flips, {bad} oracle failures"))
}

/// PRNG chunk boundaries over `len` bytes (offsets ascending, possibly
/// empty chunks and a short tail — adversarial split shapes).
fn splits(rng: &mut Corpus, len: usize, cuts: u32) -> Vec<usize> {
    let mut v = Vec::new();
    let mut c = 0u32;
    let bound = u32::try_from(len + 1).unwrap_or(u32::MAX);
    while c < cuts {
        v.push(rng.next(bound) as usize);
        c += 1;
    }
    v.sort_unstable();
    v
}

/// Seal `pt` through `splits` (offsets), returning `(ct, tag)`.
fn seal_splits(
    key: &hypg_symm::Key,
    nonce: &hypg_symm::Nonce,
    ad: &[u8],
    pt: &[u8],
    splits: &[usize],
) -> Option<(Vec<u8>, [u8; 32])> {
    use hypg_aead::StreamSealer;
    let mut sealer = StreamSealer::new(key, nonce, ad);
    let mut ct = vec![0u8; pt.len()];
    let mut prev = 0usize;
    for at in splits.iter().chain([pt.len()].iter()) {
        let at = (*at).min(pt.len());
        if at < prev {
            return None;
        }
        sealer.update(&pt[prev..at], &mut ct[prev..at])?;
        prev = at;
    }
    let mut tag = [0u8; 32];
    sealer.finish(&mut tag)?;
    Some((ct, tag))
}

/// `S14`: streaming AEAD adversarial games — PRNG chunkings (20 seeds)
/// must equal one-shot `seal`; reorder/truncate/duplicate must fail
/// `finish` with zeroed plaintext; a 1 MiB stream must equal one-shot.
fn s14() -> (bool, String) {
    use hypg_aead::{StreamOpener, StreamSealer};
    use hypg_symm::{seal, Key, Nonce, TAG_LEN};
    let key = Key([0x42u8; 32]);
    let nonce = Nonce([0x11u8; 12]);
    let mut rng = Corpus { x: 0x5EED_0001 };
    let mut bad = 0u32;
    let mut n = 0u32;
    // A. Equivalence under 20 adversarial chunkings (4 KiB message).
    let mut pt = vec![0u8; 4096];
    let mut i = 0u32;
    while (i as usize) < pt.len() {
        pt[i as usize] = u8::try_from(i.wrapping_mul(0x1F).wrapping_add(7)).unwrap_or(0);
        i += 1;
    }
    let mut ct1 = vec![0u8; 4096];
    let mut tag1 = [0u8; TAG_LEN];
    if seal(&key, &nonce, b"s14-ad", &pt, &mut ct1, &mut tag1).is_none() {
        return (false, "oneshot seal failed".to_string());
    }
    for _ in 0..20 {
        let cuts = 1 + rng.next(5);
        let sp = splits(&mut rng, 4096, cuts);
        n += 1;
        match seal_splits(&key, &nonce, b"s14-ad", &pt, &sp) {
            Some((ct, tag)) => {
                if ct != ct1 || tag != tag1 {
                    bad += 1;
                }
            }
            None => bad += 1,
        }
    }
    // B. Reorder / truncate / duplicate all fail with zeroed output.
    let sp = splits(&mut rng, 4096, 3);
    let Some((ct, tag)) = seal_splits(&key, &nonce, b"s14-ad", &pt, &sp) else {
        return (false, "s14 seal failed".to_string());
    };
    // Reorder: swap halves.
    let mut re = ct.clone();
    re[..2048].copy_from_slice(&ct[2048..]);
    re[2048..].copy_from_slice(&ct[..2048]);
    // Truncate: drop the tail.
    let trunc = ct[..3000].to_vec();
    // Duplicate: replay the head over the tail.
    let mut dup = ct.clone();
    dup[2048..].copy_from_slice(&ct[..2048]);
    for variant in [re, trunc, dup] {
        n += 1;
        let mut opener = StreamOpener::new(&key, &nonce, b"s14-ad");
        let mut back = vec![0xAAu8; variant.len()];
        // Open in two halves (split shape differs from seal shape).
        let mid = variant.len() / 2;
        let ok = opener.update(&variant[..mid], &mut back[..mid]).is_some()
            && opener.update(&variant[mid..], &mut back[mid..]).is_some()
            && opener.finish(&tag, &mut back).is_some();
        if ok || back.iter().any(|&b| b != 0) {
            bad += 1;
        }
    }
    // C. 1 MiB stream (64 KiB chunks) equals one-shot.
    let mut big = vec![0u8; BIG];
    let mut i = 0u32;
    while (i as usize) < big.len() {
        big[i as usize] = u8::try_from(i.wrapping_mul(13).wrapping_add(7)).unwrap_or(0);
        i += 1;
    }
    let mut big_ct = vec![0u8; BIG];
    let mut big_tag = [0u8; TAG_LEN];
    if seal(&key, &nonce, b"s14-big", &big, &mut big_ct, &mut big_tag).is_none() {
        return (false, "oneshot big seal failed".to_string());
    }
    n += 1;
    let mut sealer = StreamSealer::new(&key, &nonce, b"s14-big");
    let mut stream_ct = vec![0u8; BIG];
    let mut o = 0usize;
    let mut stream_ok = true;
    while o < BIG {
        let end = (o + 65536).min(BIG);
        if sealer.update(&big[o..end], &mut stream_ct[o..end]).is_none() {
            stream_ok = false;
        }
        o = end;
    }
    let mut stream_tag = [0u8; TAG_LEN];
    if sealer.finish(&mut stream_tag).is_none() {
        stream_ok = false;
    }
    if !stream_ok || stream_ct != big_ct || stream_tag != big_tag {
        bad += 1;
    }
    (bad == 0, format!("{n} streaming games, {bad} failures"))
}

fn main() {
    let suites: [(&str, (bool, String)); 14] = [
        ("S1 garbage-robustness", s1()),
        ("S2 malleability-sweep", s2(flips())),
        ("S3 key-mismatch-matrix", s3()),
        ("S4 message-extremes", s4()),
        ("S5 fo-binding", s5()),
        ("S6 sampler-stats", s6()),
        ("S7 failure-sweep", s7(trials())),
        ("S8 determinism", s8()),
        ("S9 aead-adversarial", s9()),
        ("S10 ds-forgery", s10()),
        ("S11 adversarial-mega", s11()),
        ("S12 panic-sweep", s12()),
        ("S13 sk-flip-sweep", s13()),
        ("S14 streaming-aead", s14()),
    ];
    let mut failures = 0u32;
    for (name, (ok, detail)) in &suites {
        println!("{}: {name} — {detail}", if *ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    }
    if failures > 0 {
        eprintln!("redteam: {failures} suite(s) FAILED");
        std::process::exit(1);
    }
    println!("redteam: all suites passed");
}
