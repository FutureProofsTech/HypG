//! `hypg-ds`: stateless hash-based signatures (`HypG` signature pillar).
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`.
//!
//! SLH-DSA-256f-shaped composition (FORS + hypertree of XMSS/WOTS+),
//! all hashes via keyed BLAKE3 and `CA-PRF` addressing. See
//! `docs/spec-ds.md` for parameters, the constant-time rule (WOTS+
//! chains always run all `w − 1` steps with branchless select), and the
//! honest security position: NIST Category-5 *dimensions*, no exact
//! proof for this composition, no signing-volume bound, not a security
//! certification. Wire/spec revision is 2.0.1; see `CHANGELOG.md`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Fixed protocol buffers (~50 KB signatures, 16-leaf tree levels) live on
//! the stack by policy: heap allocation is banned, so `large_stack_arrays`
//! is the intended shape, not an accident.
#![allow(clippy::large_stack_arrays)]

pub mod addr;
pub mod fors;
pub mod hypertree;
pub mod params;
pub mod slh;
pub mod thash;
pub mod wots;
pub mod xmss;

pub use params::{SIG_LEN, SIG_PK_LEN, SIG_SK_LEN};
pub use slh::{ds_keygen, ds_sign, ds_verify, pre_sign, serialize_sig, PreSign, SigPk, SigSk};
// Parallel building blocks for threaded signers (`hypg-mt`): pure
// functions of their inputs; outputs byte-identical to serial paths.
pub use fors::{fors_sign_one, ForsSig};
pub use hypertree::LayerSig;
pub use xmss::{xmss_build, xmss_sign_with_leaves};
