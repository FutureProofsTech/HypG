# Domain-separation registry (normative)

Single registry for every hash/XOF/KDF/`CA-PRF`/`derive_key` domain string
in the workspace. Rationale: with three pillars sharing `hypg-core`
primitives, a collision (same `(input, domain)` pair meaning two things)
would be a cross-protocol attack. Rule: **a new domain needs a new row
here plus a one-line rationale; frozen rows are never edited.**

Prefix grammar: `HYP-G/<ver>/<subsystem>-<purpose>`, ASCII, ≤ 32 bytes.

v0.7 bumped every live row from `v03`/`v05` to `v07` to mark the
BLAKE3/ChaCha migration (same names otherwise); KATs re-frozen.
History: `v03`/`v05` rows are recorded in git history, not here.

## Frozen rows (`v07`, KEM — do not touch; KAT-pinned)

| Domain | Used for |
|---|---|
| `HYP-G/v07/seed-a` | KEM `seed_a` derivation |
| `HYP-G/v07/sec-s`, `sec-e` | KEM secret/error vectors |
| `HYP-G/v07/poly-a` | KEM matrix `A` expansion |
| `HYP-G/v07/rand-r`, `rand-e1`, `rand-e2` | KEM encryption randomness (FO `G`) |
| `HYP-G/v07/fake` | KEM implicit-rejection key |
| `HYP-G/v07/r-seed` | KEM FO randomness seed (`BLAKE3(m‖pk)`) |
| `HYP-G/v07/ss`, `reject` | KEM shared-secret / rejection KDFs |

## Frozen rows (`v07`, Symm + DS — do not touch; KAT-pinned)

| Domain | Used for |
|---|---|
| `HYP-G/v07/symm-enc` | AEAD encryption subkey (`derive_key`) |
| `HYP-G/v07/symm-mac` | AEAD MAC subkey (`derive_key`) |
| `HYP-G/v07/kat` | Hash-pillar KAT `derive32` sample only (test vectors, never protocol use) |
| `HYP-G/v07/ds-pubseed` | DS `pubseed` derivation from `esk` |
| `HYP-G/v07/ds-prf` | DS `sk.prf` slot derivation from `esk` |
| `HYP-G/v07/ds-addrnd` | DS hedged randomizer (`R = CA-PRF(sk.prf, msg)`) |
| `HYP-G/v07/ds-msghash` | DS message digest (streamed, counter-bound) |

Note: DS tweak hashes bind `pubseed` as the BLAKE3 key and `ADRS`
(incl. its type field) as input — no separate per-call domain strings,
which the v05 design needed for prefix-SHA3. The retired v05
`ds-fors`/`ds-wots`/`ds-tree` strings must not be reused.

`CA-PRF` internal `-init`/`-out` suffixes (see `caprf.rs`) are part of
the mechanism, not the registry: distinct caller domains already imply
distinct expander outputs.
