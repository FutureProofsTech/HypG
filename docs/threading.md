# Threading model

**Status:** descriptive. Threading is a performance feature of the
`std`-only `hypg-mt` crate. It adds no cryptographic primitive and no
security claim.

## 1. Boundary: threads are a platform capability

The `no_std` crates (`hypg-core`, `hypg-kem`, `hypg-symm`, `hypg-aead`,
`hypg-ds`, `hypg-hash`) never spawn threads. They have no scheduler, no
thread-local storage, and no assumption of an 8 MB host stack. Their
entry points are pure functions of borrowed inputs and caller-owned
output buffers.

All threading lives in `hypg-mt`, a zero-external-dependency `std`
library. It uses `std::thread::scope` only:

- no `rayon`, because external dependencies are forbidden;
- no detached `spawn` with `'static` bounds, because scoped threads can
  borrow the caller's key material without copying;
- no mutexes or atomics, because workers do not share mutable state.

The `no_std` libraries remain usable on embedded targets that have no
threads.

## 2. What parallelizes

One DS signature consists of:

- a short serial prelude: randomizer, message digest, and digest split;
- 17 independent XMSS tree builds;
- 35 independent FORS tree builds;
- a short serial assembly: WOTS signs, tree climbs, and serialization.

The tree builds are pairwise independent: each is a pure function of
`(pubseed, esk, tree geometry, indices)` fixed by the digest. The 52
build units dominate signing time. On the recorded machine, one XMSS
layer public-key build is about 3.80 ms and one FORS sign is about
7.77 ms; the total serial sign is about 72.0 ms.

`hypg-mt::mt_sign` scatters the 52 units across scoped workers with a
strided assignment: worker `w` takes units `w, w+W, w+2W, ...`. The
striding balances the roughly 100× cost difference between a full XMSS
build and a FORS unit better than a contiguous split. Workers return
owned results; the main thread joins and assembles in unit order.

Serial `ds_sign` remains canonical. It is the path used by KATs,
`no_std` targets, and any caller that does not want a thread pool.

## 3. Determinism argument

The output bytes are independent of scheduling because:

1. Each unit is a pure function of immutable inputs and returns owned
   arrays.
2. Workers do not write to shared mutable state.
3. The join loop places each result into an index-derived slot; the
   assembly then reads slots in fixed index order.
4. The serial assembly path (`xmss_sign_with_leaves`, root
   recomputation, climbs, `serialize_sig`) matches the serial signer.

The tests pin this:

- `mt_matches_serial`: four messages, including empty, short, and
  1500-byte inputs, compared byte-for-byte with `ds_sign`.
- `mt_stable_across_worker_counts`: 1, 2, and 64 workers produce the
  same signature.

The DS KATs are the external byte-level anchor.

## 4. Safety argument

- `std::thread::scope` guarantees that all scoped workers are joined
  before the scope returns. There are no detached threads.
- Each worker owns its `Vec` of work units and returns owned outputs.
  Shared references are read-only.
- Every shared type is an owned array, integer, or byte buffer. There is
  no `Rc`, `RefCell`, `Mutex`, or interior mutability in the tree.
- `#![forbid(unsafe_code)]` applies to `hypg-mt` as well.
- If a worker thread is lost (a platform failure, not a cryptographic
  error), the join loop recomputes that worker's chunk serially with the
  same assignment. The function is total and does not panic on join
  failure.
- Gather buffers containing secret FORS leaves and XMSS leaves are
  wiped before the vectors drop.

The compiler enforces `Send`/`Sync` for the scoped borrows. The
concurrency audit surface is the orchestration code in
`crates/hypg-mt/src/lib.rs`.

## 5. Worker sizing

```text
worker_count() =
  HYPG_MT_WORKERS, if set to an integer in [1,64];
  otherwise available_parallelism().clamp(1,64).
```

`mt_sign` further clamps to `D + FORS_K = 52` units. `mt_sign_with_workers`
clamps to `[1,64]` and then to the unit count.

The recorded benchmark used 16 workers on an i5-14400F (10 cores, 16
threads):

| Operation | Average | Speedup |
|---|---:|---:|
| Serial `ds_sign` | 72,009 µs | 1.000× |
| `mt_sign` | 18,329 µs | **3.928×** |

The speedup is sublinear because:

- the 17 XMSS units and 35 FORS units have different costs;
- 52 units do not divide evenly across 16 workers;
- the digest and serial assembly are not parallelized;
- thread creation and joining have overhead;
- the machine has 10 physical cores, not 16 independent cores.

Oversubscription past the useful unit count does not help. The clamp
exists to avoid pathological thread counts.

## 6. Memory and stack

`hypg-mt` uses `Vec` for per-unit results and boxes the large hypertree
signature. This is legitimate because it is a `std` crate. The `no_std`
DS signer takes a caller-provided `&mut [u8; SIG_LEN]` and keeps its
large objects on the stack; the KAT and CLI box the signature where
appropriate.

Thread stacks are platform-dependent. The implementation does not
provide a custom stack allocator. A caller that constrains stack size
must test its own configuration; the CI 1 MB-stack gate runs the KAT
and red-team binaries, not arbitrary threaded workloads.

## 7. Non-goals

- No threading inside the `no_std` libraries.
- No parallel KEM. KEM operations are microsecond-scale; thread overhead
  would dominate. Batch independent KEM operations at the application
  layer if needed.
- No parallel verification fast path. Verification is already much
  faster than signing, and parallel verification complicates the
  timing story.
- No cross-signature caching. Caching introduces state, a cache-timing
  surface, and key-reuse hazards.
- No persistent thread pool. Scoped threads are created per call; a pool
  would add state and lifetime complexity.
- No claim that threading improves side-channel resistance. It can
  change timing and cache behaviour, which is a reason for caution, not
  a benefit.

## 8. Limitations

The threaded signer is byte-identical and tested, but:

- it is not constant-time;
- it is not evaluated for cache or scheduler side channels;
- it does not reduce the deterministic-signature privacy loss;
- it does not enforce a signing-volume limit;
- it is not part of the `no_std` profile;
- its performance depends on the host scheduler and CPU topology.

Use it as an optional host-side acceleration, not as a security feature.
