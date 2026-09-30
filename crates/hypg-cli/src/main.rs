//! `hypg-cli`: operator key management (std binary, zero-dep).
//!
//! ```text
//! hypg-cli keygen [--seed HEX64]        # prints pk_hex + sk_hex
//! hypg-cli encaps <pk_hex> [--coins HEX64]  # prints ct_hex + ss_hex
//! hypg-cli decaps <sk_hex> <ct_hex>     # prints ss_hex
//! hypg-cli seal <key64> <nonce24> <ad_hex> <pt_hex>   # prints ct_hex + tag_hex
//! hypg-cli open <key64> <nonce24> <ad_hex> <ct_hex> <tag64>  # prints pt_hex
//! hypg-cli hash <hex>                   # prints b3_256 hex
//! ```
//!
//! Without `--seed`/`--coins`, randomness comes from the OS
//! (`/dev/urandom`; one 32-byte read per missing value). The library
//! itself stays `no_std` without I/O; all OS interaction lives here.
//!
//! Exit codes: `0` = success (including KEM decapsulation, which never
//! fails — forgeries yield a pseudorandom `ss` instead); `2` = usage or
//! input error (bad hex, wrong lengths, unknown subcommand); `3` =
//! authentication failure (forged `ct`/`tag` in `open`, bad `sig` in
//! `ds-verify`). Scripts must treat `3` as "peer/message untrusted",
//! not as a CLI bug.

use std::io::Read;

use hypg_kem::{decaps, encaps, keygen, Ciphertext, PublicKey, SecretKey};
use hypg_symm::{open, seal, Key, Nonce, TAG_LEN};

const USAGE: &str = "usage:
  hypg-cli keygen [--seed HEX64]
  hypg-cli encaps <pk_hex> [--coins HEX64]
  hypg-cli decaps <sk_hex> <ct_hex>
  hypg-cli seal <key64> <nonce24> <ad_hex> <pt_hex>
  hypg-cli open <key64> <nonce24> <ad_hex> <ct_hex> <tag64>
  hypg-cli hash <hex>
  hypg-cli ds-keygen [--esk HEX64]
  hypg-cli ds-sign <sk_hex> <msg_hex>
  hypg-cli ds-verify <pk_hex> <msg_hex> <sig_hex>";

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}

fn from_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, bytes.len()));
    }
    let mut out = [0u8; N];
    let mut i = 0usize;
    while i < N {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

fn from_hex_vec(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(format!("odd hex length: {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

/// One 32-byte OS-random read. Fails closed (no fallback PRNG).
fn os_random32() -> Result<[u8; 32], String> {
    let mut f =
        std::fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf).map_err(|e| format!("read /dev/urandom: {e}"))?;
    Ok(buf)
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

/// CLI failure with a process exit code: `2` = usage/input error,
/// `3` = authentication failure (forged `ct`/`tag`/`sig`).
struct CliError {
    code: i32,
    msg: String,
}

impl From<String> for CliError {
    fn from(msg: String) -> Self {
        Self { code: 2, msg }
    }
}

impl From<&str> for CliError {
    fn from(msg: &str) -> Self {
        Self { code: 2, msg: msg.to_string() }
    }
}

fn auth_fail(msg: &str) -> CliError {
    CliError { code: 3, msg: msg.to_string() }
}

fn cmd_keygen(args: &[String]) -> Result<String, CliError> {
    if args.len() > 3 {
        return Err(CliError::from(USAGE));
    }
    let seed: [u8; 32] = match flag_value(args, "--seed") {
        Some(h) => from_hex(&h)?,
        None => os_random32()?,
    };
    let (pk, sk) = keygen(&seed);
    Ok(format!("pk={}\nsk={}\n", to_hex(&pk.0), to_hex(&sk.0)))
}

fn cmd_encaps(args: &[String]) -> Result<String, CliError> {
    if args.len() < 2 || args.len() > 4 {
        return Err(CliError::from(USAGE));
    }
    let pk = PublicKey(from_hex(&args[1])?);
    let coins: [u8; 32] = match flag_value(args, "--coins") {
        Some(h) => from_hex(&h)?,
        None => os_random32()?,
    };
    let (ct, ss) = encaps(&pk, &coins);
    Ok(format!("ct={}\nss={}\n", to_hex(&ct.0), to_hex(&ss.0)))
}

fn cmd_decaps(args: &[String]) -> Result<String, CliError> {
    if args.len() != 3 {
        return Err(CliError::from(USAGE));
    }
    let sk = SecretKey(from_hex(&args[1])?);
    let ct = Ciphertext(from_hex(&args[2])?);
    let ss = decaps(&sk, &ct);
    Ok(format!("ss={}\n", to_hex(&ss.0)))
}

fn cmd_seal(args: &[String]) -> Result<String, CliError> {
    if args.len() != 5 {
        return Err(CliError::from(USAGE));
    }
    let key = Key(from_hex(&args[1])?);
    let nonce = Nonce(from_hex(&args[2])?);
    let ad = from_hex_vec(&args[3])?;
    let pt = from_hex_vec(&args[4])?;
    let mut ct = vec![0u8; pt.len()];
    let mut tag = [0u8; TAG_LEN];
    seal(&key, &nonce, &ad, &pt, &mut ct, &mut tag).ok_or("seal: length mismatch")?;
    Ok(format!("ct={}\ntag={}\n", to_hex(&ct), to_hex(&tag)))
}

fn cmd_open(args: &[String]) -> Result<String, CliError> {
    if args.len() != 6 {
        return Err(CliError::from(USAGE));
    }
    let key = Key(from_hex(&args[1])?);
    let nonce = Nonce(from_hex(&args[2])?);
    let ad = from_hex_vec(&args[3])?;
    let ct = from_hex_vec(&args[4])?;
    let tag: [u8; TAG_LEN] = from_hex(&args[5])?;
    let mut pt = vec![0u8; ct.len()];
    open(&key, &nonce, &ad, &ct, &tag, &mut pt)
        .ok_or_else(|| auth_fail("open: authentication failure"))?;
    Ok(format!("pt={}\n", to_hex(&pt)))
}

fn cmd_hash(args: &[String]) -> Result<String, CliError> {
    if args.len() != 2 {
        return Err(CliError::from(USAGE));
    }
    let input = from_hex_vec(&args[1])?;
    let mut out = [0u8; 32];
    hypg_symm::symm_hash(&input, &mut out);
    Ok(format!("b3_256={}\n", to_hex(&out)))
}

fn cmd_ds_keygen(args: &[String]) -> Result<String, CliError> {
    if args.len() > 3 {
        return Err(CliError::from(USAGE));
    }
    let esk: [u8; 32] = match flag_value(args, "--esk") {
        Some(h) => from_hex(&h)?,
        None => os_random32()?,
    };
    let (pk, sk) = hypg_ds::ds_keygen(&esk);
    Ok(format!("ds_pk={}\nds_sk={}\n", to_hex(&pk.0), to_hex(&sk.0)))
}

fn cmd_ds_sign(args: &[String]) -> Result<String, CliError> {
    if args.len() != 3 {
        return Err(CliError::from(USAGE));
    }
    let sk = hypg_ds::SigSk(from_hex(&args[1])?);
    let msg = from_hex_vec(&args[2])?;
    #[allow(clippy::large_stack_arrays)]
    let mut sig = Box::new([0u8; hypg_ds::SIG_LEN]); // heap-boxed immediately
    hypg_ds::ds_sign(&sk, &msg, &mut sig);
    Ok(format!("sig={}\n", to_hex(&sig[..])))
}

fn cmd_ds_verify(args: &[String]) -> Result<String, CliError> {
    if args.len() != 4 {
        return Err(CliError::from(USAGE));
    }
    let pk = hypg_ds::SigPk(from_hex(&args[1])?);
    let msg = from_hex_vec(&args[2])?;
    let sig = from_hex_vec(&args[3])?;
    if hypg_ds::ds_verify(&pk, &msg, &sig[..]) {
        Ok("verify=ok\n".to_string())
    } else {
        Err(auth_fail("verify: BAD signature"))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = if args.len() >= 2 && args[1] == "keygen" {
        cmd_keygen(&args[1..])
    } else if args.len() >= 2 && args[1] == "encaps" {
        cmd_encaps(&args[1..])
    } else if args.len() >= 2 && args[1] == "decaps" {
        cmd_decaps(&args[1..])
    } else if args.len() >= 2 && args[1] == "seal" {
        cmd_seal(&args[1..])
    } else if args.len() >= 2 && args[1] == "open" {
        cmd_open(&args[1..])
    } else if args.len() >= 2 && args[1] == "hash" {
        cmd_hash(&args[1..])
    } else if args.len() >= 2 && args[1] == "ds-keygen" {
        cmd_ds_keygen(&args[1..])
    } else if args.len() >= 2 && args[1] == "ds-sign" {
        cmd_ds_sign(&args[1..])
    } else if args.len() >= 2 && args[1] == "ds-verify" {
        cmd_ds_verify(&args[1..])
    } else {
        Err(CliError::from(USAGE))
    };
    match out {
        Ok(s) => print!("{s}"),
        Err(e) => {
            eprintln!("hypg-cli: {}", e.msg);
            std::process::exit(e.code);
        }
    }
}
