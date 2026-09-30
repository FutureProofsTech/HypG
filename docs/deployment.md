# Deployment guide (HypG v0.4.0 — prototype, not production)

This library is a research prototype (`0.x`, hardness unconfirmed).
If you still evaluate it in a test system, follow this page exactly.
Deviations void every property below.

## 1. Randomness (critical)

The libraries contain **no RNG** (`no_std`, no OS interface). Randomness
quality is entirely the caller's responsibility:

- `keygen(seed)`: `seed` must be 32 bytes from a CSPRNG. Never hardcode,
  never derive from time/PID, never reuse across keypairs.
- `encaps(pk, coins)`: `coins` must be fresh 32 CSPRNG bytes per call.
  Reusing `coins` with the same `pk` reuses the FO message (and hence the
  ciphertext core) — catastrophic for CCA security.
- The `hypg-cli` binary reads `/dev/urandom` (one 32-byte `read_exact`
  per missing value) and fails closed on I/O error. It exists so
  operators never hand-roll randomness; prefer it over direct API use
  in scripts. Embedded callers must use their platform TRNG/HWRNG.

## 2. Key handling

- `sk` layout is `seed || fake || pk`. Store it with owner-only file
  permissions; consider `mlock`/`mlockall` + `madvise(DONTDUMP)` in the
  *calling* process (the lib cannot do this: `no_std`, no syscalls).
- Call `sk.zeroize()` / `ss.zeroize()` before dropping key material.
  This is best-effort safe-Rust erasure (no `unsafe` volatile); assume a
  sufficiently motivated memory-scanning adversary with swap access
  still wins — disable swap for the key-handling process.
- `ss` must go directly into a KDF for session keys; never use raw `ss`
  bytes as a stream key, never compare `ss` values with `==` across
  parties (use them, don't test them — equality oracles aid attackers).

## 3. API mapping (NIST-style)

| NIST `crypto_kem_*` | HypG equivalent |
|---|---|
| `keypair(pk, sk)` + `randombytes` | `hypg-cli keygen` (OS-random) or `keygen(&csp_rng_32())` |
| `enc(pk, ct, ss)` | `hypg-cli encaps <pk> [ --coins … ]` or `encaps(&pk, &fresh_coins)` |
| `dec(sk, ct)` → `ss` (implicit reject) | `hypg-cli decaps <sk> <ct>` or `decaps(&sk, &ct)` — **never fails**; a forged `ct` yields a random-looking `ss`, never an error. Do not add your own validity check on `ss` (that would break implicit rejection). |

Sizes: `pk`/`ct` 800 B, `sk` 864 B, `ss`/`seed`/`coins` 32 B.

## 3b. Symmetric + signature operator rules (v0.7+)

- AEAD (ChaCha20 + keyed-BLAKE3 EtM): never reuse a `nonce` under one
  `key` (destroys confidentiality; authenticity survives).
  `hypg-cli seal` takes an explicit 12-byte nonce — supply OS-random
  bytes (e.g. from `/dev/urandom`) or a persistent counter. Rekey after
  ~2⁴⁸ messages. One `(key, nonce)` pair covers messages below 256 GiB.
- Signatures: stateless — no clone hazard, unlimited messages per key.
  `esk` (32 B) is the root secret: `hypg-cli ds-keygen` without `--esk`
  samples it from the OS. Transport the full 35456-byte `sig`; verify
  rejects short/long/truncated inputs without indexing them. Bind the
  64-byte `pk` out-of-band exactly like a KEM `pk`.
- Zeroize `sk`/`ss`/AEAD keys after use (`zeroize()` methods); same
  `mlock`/swap guidance as §2.

## 4. Transport rules

- Always send the full 800-byte `ct`; truncation is handled safely
  (rejection → random `ss`) but wastes a round trip.
- Bind `pk` to the peer out-of-band (TOFU at minimum, signatures or
  a directory for anything serious). The KEM authenticates nothing by
  itself — an active attacker who swaps `pk` owns the session.
- Rekey before ~2⁴⁸ encapsulations per keypair (conservative rotation
  bound; no rekey-forward-secrecy is provided within a keypair).

## 5. Side-channel posture

- The implementation is branchless w.r.t. secrets (fixed loops, no
  secret indices, mask-only modular reduction) and shows no valid/invalid
  `decaps` timing split locally (Welch `|t| = 0.34`, `n = 5000`,
  `docs/metrics.md`). That is a *smoke* result on one machine, not a
  proof: no power/EM/fault analysis exists. Do not run decapsulation
  where an adversary measures power or injects faults without additional
  hardening (shielding, redundancy, verification) this project does not
  supply.

## 6. What still blocks production (`1.0`)

Lattice-estimator confirmation, `dudect`-grade timing, third-party audit
(see `docs/estimator.md`, `docs/audit-prep.md`). Until all land, keep
HypG in test systems with explicit `0.x` version pins.
