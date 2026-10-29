//! `hypg-cli` failure-path tests: every malformed input must fail closed
//! with a documented exit code (`2` = usage/input error, `3` =
//! authentication failure), and KEM decapsulation must never fail
//! (implicit rejection → exit `0` with an unrelated `ss`).
//!
//! These run the real binary via `CARGO_BIN_EXE_hypg-cli`, so they also
//! cover argument parsing, hex decoding, and length checks end to end.

use std::fmt::Write as _;
use std::process::{Command, Output};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hypg-cli"))
}

fn run(args: &[&str]) -> Output {
    cli().args(args).output().expect("spawn hypg-cli")
}

fn code_of(out: &Output) -> i32 {
    out.status.code().expect("exit code present")
}

fn hex_of(byte: u8, nbytes: usize) -> String {
    let mut s = String::with_capacity(nbytes * 2);
    for _ in 0..nbytes {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn stdout_field(out: &Output, key: &str) -> String {
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(v) = line.strip_prefix(key) {
            return v.to_string();
        }
    }
    panic!("field {key} missing in stdout: {s}");
}

fn flip_last_hex_char(h: &str) -> String {
    let mut v = h.to_string();
    let last = v.pop().expect("non-empty hex");
    v.push(if last == '0' { '1' } else { '0' });
    v
}

#[test]
fn no_args_exit_2() {
    let out = run(&[]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn unknown_command_exit_2() {
    let out = run(&["frobnicate"]);
    assert_eq!(code_of(&out), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
}

#[test]
fn keygen_bad_seed_length_exit_2() {
    let out = run(&["keygen", "--seed", "42"]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn keygen_odd_hex_exit_2() {
    let out = run(&["keygen", "--seed", "abc"]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn keygen_bad_hex_char_exit_2() {
    let mut bad = hex_of(0x42, 32);
    bad.replace_range(0..2, "zz");
    let out = run(&["keygen", "--seed", &bad]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn encaps_bad_pk_length_exit_2() {
    let out = run(&["encaps", "4242"]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn encaps_bad_pk_char_exit_2() {
    let out = run(&["encaps", &hex_of(0x42, 1568).replace('4', "z")]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn decaps_wrong_sk_length_exit_2() {
    let out = run(&["decaps", &hex_of(0x42, 32), &hex_of(0x11, 1440)]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn seal_bad_key_length_exit_2() {
    let out = run(&["seal", "42", &hex_of(0x11, 12), "6164", "7070"]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn open_bad_nonce_length_exit_2() {
    let out = run(&["open", &hex_of(0x42, 32), "11", "6164", "7070", &hex_of(0x00, 32)]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn hash_bad_hex_exit_2() {
    let out = run(&["hash", "zz"]);
    assert_eq!(code_of(&out), 2);
}

#[test]
fn ds_sign_bad_sk_length_exit_2() {
    let out = run(&["ds-sign", &hex_of(0x43, 32), "6164"]);
    assert_eq!(code_of(&out), 2);
}

fn seal_once() -> (String, String, String) {
    // Returns `(ct_hex, tag_hex, pt_hex)` for fixed key/nonce/ad/pt.
    let key = hex_of(0x42, 32);
    let nonce = hex_of(0x11, 12);
    let out = run(&["seal", &key, &nonce, "6164", "7070"]);
    assert_eq!(code_of(&out), 0);
    (stdout_field(&out, "ct="), stdout_field(&out, "tag="), "7070".to_string())
}

#[test]
fn open_forged_tag_exit_3() {
    let (ct, tag, _) = seal_once();
    let out = run(&[
        "open",
        &hex_of(0x42, 32),
        &hex_of(0x11, 12),
        "6164",
        &ct,
        &flip_last_hex_char(&tag),
    ]);
    assert_eq!(code_of(&out), 3);
    assert!(String::from_utf8_lossy(&out.stderr).contains("authentication failure"));
}

#[test]
fn open_forged_ct_exit_3() {
    let (ct, tag, _) = seal_once();
    let out = run(&[
        "open",
        &hex_of(0x42, 32),
        &hex_of(0x11, 12),
        "6164",
        &flip_last_hex_char(&ct),
        &tag,
    ]);
    assert_eq!(code_of(&out), 3);
}

#[test]
fn open_wrong_ad_exit_3() {
    let (ct, tag, _) = seal_once();
    let out = run(&["open", &hex_of(0x42, 32), &hex_of(0x11, 12), "6165", &ct, &tag]);
    assert_eq!(code_of(&out), 3);
}

#[test]
fn open_wrong_key_exit_3() {
    let (ct, tag, _) = seal_once();
    let out = run(&["open", &hex_of(0x43, 32), &hex_of(0x11, 12), "6164", &ct, &tag]);
    assert_eq!(code_of(&out), 3);
}

fn ds_fixture() -> (String, String, String) {
    // Returns `(pk_hex, msg_hex, sig_hex)` for fixed `esk`/message.
    let esk = hex_of(0x43, 32);
    let out = run(&["ds-keygen", "--esk", &esk]);
    assert_eq!(code_of(&out), 0);
    let pk = stdout_field(&out, "ds_pk=");
    let sk = stdout_field(&out, "ds_sk=");
    let out = run(&["ds-sign", &sk, "6164"]);
    assert_eq!(code_of(&out), 0);
    (pk, "6164".to_string(), stdout_field(&out, "sig="))
}

#[test]
fn ds_verify_forged_sig_exit_3() {
    let (pk, msg, sig) = ds_fixture();
    let out = run(&["ds-verify", &pk, &msg, &flip_last_hex_char(&sig)]);
    assert_eq!(code_of(&out), 3);
    assert!(String::from_utf8_lossy(&out.stderr).contains("BAD signature"));
}

#[test]
fn ds_verify_wrong_msg_exit_3() {
    let (pk, _, sig) = ds_fixture();
    let out = run(&["ds-verify", &pk, "6165", &sig]);
    assert_eq!(code_of(&out), 3);
}

#[test]
fn ds_verify_truncated_sig_exit_3() {
    // Length mismatch is still an authentication failure (fail closed),
    // never a parse panic.
    let (pk, msg, sig) = ds_fixture();
    let out = run(&["ds-verify", &pk, &msg, &sig[..sig.len() - 2]]);
    assert_eq!(code_of(&out), 3);
}

#[test]
fn decaps_garbage_ct_exit_0_and_differs() {
    // Implicit rejection at the operator boundary: no panic, exit 0,
    // and the forged `ss` differs from the honest one.
    let seed = hex_of(0x42, 32);
    let out = run(&["keygen", "--seed", &seed]);
    assert_eq!(code_of(&out), 0);
    let pk = stdout_field(&out, "pk=");
    let sk = stdout_field(&out, "sk=");
    let out = run(&["encaps", &pk, "--coins", &seed]);
    assert_eq!(code_of(&out), 0);
    let ct = stdout_field(&out, "ct=");
    let honest = stdout_field(&out, "ss=");
    let bad_ct = flip_last_hex_char(&ct);
    let out = run(&["decaps", &sk, &bad_ct]);
    assert_eq!(code_of(&out), 0);
    assert_ne!(stdout_field(&out, "ss="), honest);
    // Zero key is valid input too (fixed-point check, no panic).
    let out = run(&["decaps", &hex_of(0x00, 1632), &hex_of(0x00, 1440)]);
    assert_eq!(code_of(&out), 0);
}
