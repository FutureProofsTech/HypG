# Threading model (HypG)

How multithreading works here — and, by design, where it does not.

## 1. The boundary: threads are a platform capability, not a primitive

The `no_std` libraries (`hypg-core`, `hypg-kem`, `hypg-symm`,
`hypg-ds`) never spawn threads: there is no scheduler, no thread-local
storage, and no 8 MB stacks to assume on embedded targets. All library
entry points are pure functions of their inputs (`&` in, values out),
which is exactly what makes them parallelizable *by callers*.

All threading lives in `hypg-mt` (std library crate, zero-dep):
`std::thread::scope` only — no `rayon` (dependency policy), no manual
`spawn` + `join` with `'static` bounds (scope lets workers borrow the
caller's buffers, so nothing is copied and lifetimes are checked).

## 2. What parallelizes (DS signing)

One DS signature = digest (µs, serial) + 12 full XMSS tree builds +
30 FORS tree builds (~90% of time, pairwise independent) + fast serial
assembly (12 WOTS signs, climbs, serialize). The trees do not depend on
each other — only on `(esk, pubseed, indices)` fixed by the digest —
so any schedule computes the same bytes.

`hypg-mt::mt_sign` runs the 42 builds on scoped workers (strided
assignment: worker `w` takes units `w, w+W, …`, balancing the ~100×
XMSS/FORS cost skew), joins, then assembles in index order. The serial
`ds_sign` is unchanged and remains canonical (KATs, `no_std` targets).

## 3. Why output is byte-identical (not just "usually")

- Units are pure functions: `xmss_build`, `fors_sign_one` take all
  inputs by value/borrow and return owned outputs. No shared mutable
  state exists anywhere in the wave.
- Workers return owned results; the join loop places each into its
  indexed slot. Scheduling affects *timing only* — there is no code
  path where order influences bytes.
- Assembly (`xmss_sign_with_leaves`, `fors_verify` for roots, climbs,
  `serialize_sig`) is the same serial code path shape as `ds_sign`.
- Pinned by tests: `mt_matches_serial` (4 messages incl. empty/1.5 KB)
  and `mt_stable_across_worker_counts` (1/2/64 workers → identical).
  Change any unit and these fail before KATs even run.

## 4. Safety argument (why there are no data races to audit)

- `std::thread::scope` guarantees all workers join before return; no
  detached threads, no `'static` smuggling.
- Each worker owns its chunk (`Vec<Unit>` moved in) and returns owned
  results. The only shared borrows are `&` (read-only key material).
  `Send` holds throughout because every type is owned arrays/`u32`/`u64`
  — no `Rc`, `RefCell`, or interior mutability exists in the tree.
- The compiler checks all of this; there is no `unsafe`, no mutex, no
  atomics. The audit surface for concurrency is this page plus 60 lines
  of orchestration.

## 5. Worker sizing and expectations

`worker_count()` = `available_parallelism()` clamped to `[1, 64]`,
overridable with `HYPG_MT_WORKERS` (tests pin 1/2/64). Measured on
i5-14400F (16 threads): serial ≈ 65 ms → threaded ≈ 12 ms (**5.5×**).
Scaling is sublinear (serial digest/assembly + wave quantization), and
oversubscription past core count adds nothing — the clamp exists so a
64-core server doesn't spawn silly thread counts for a 42-unit wave.

## 6. Deliberate non-goals

- No parallelism inside `no_std` libs (would break embedded targets).
- No parallel KEM (ops are µs-scale; thread overhead would dominate —
  batch across operations in your own code instead: `ds_sign`-style
  entry points are all pure and `Send`-safe to call from scopes).
- No parallel verification fast path needed (verify is already ~30×
  faster than serial sign; threading it would complicate the
  timing-independence story for single-digit-ms gains).
- No cross-signature caching (statefulness + cache-timing surface;
  see the optimization plan's non-goals).
