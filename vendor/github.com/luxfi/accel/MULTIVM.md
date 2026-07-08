# Multi-VM GPU Sessions

`accel.VMSession` provides per-VM GPU isolation, ordering, and priority for
the 11 native chains running inside a single `luxd` process. The legacy
`accel.DefaultSession()` continues to work for callers that want to share the
process-wide GPU.

## Why per-VM sessions

A single `luxd` instance hosts up to 17 chains (P/X/C + 14 native VMs). Several
of those chains run latency-sensitive cryptography on the hot path:

- C-Chain (cevm) — block building, log/receipt hashing
- D-Chain (dexvm) — order matching with 1ms blocks
- K-Chain (keyvm) — ML-KEM/ML-DSA on cross-chain hot path
- Z-Chain (zkvm) — Groth16 verification, Poseidon hashing
- B-Chain (bridgevm) — ECDSA batch verification of MPC signatures
- T-Chain (thresholdvm) — FHE bootstrapping
- Q-Chain (quantumvm) — Dilithium signing/verification

Sharing one global session means:

- A long FHE bootstrap on T-Chain can stall a 1ms DEX order match.
- A misbehaving VM that holds a session lock blocks every other VM.
- There is no way to assign more GPU time to consensus-critical paths.
- Closing the session (e.g. on plugin restart) tears down everyone.

`VMSession` solves all four with explicit per-VM isolation.

## API

```go
sess, err := accel.NewVMSession("dexvm",
    accel.WithPriority(accel.PriorityHigh),
    accel.WithMemoryBudget(2 << 30), // 2 GiB cap
)
if err != nil {
    return err
}
defer sess.Close()

// Submit a GPU op. Within this session, ops complete in submission order.
err = sess.Submit(ctx, func(s *accel.Session) error {
    return s.Crypto().BLSVerifyBatch(msgs, sigs, pks, results)
})
```

### Options

| Option | Purpose | Default |
|--------|---------|---------|
| `WithPriority(p)` | Dispatch priority for scheduling | `PriorityNormal` |
| `WithMemoryBudget(n)` | Hard cap on cumulative allocations (bytes) | unlimited |
| `WithVMBackend(b)` | Pin to CUDA/Metal/WebGPU | auto |
| `WithQueueDepth(n)` | In-flight op queue depth | 1024 |
| `WithSharedDevice()` | Use the process-wide default Session handle | own session |

### Priorities

| Constant | Value | Use |
|----------|-------|-----|
| `PriorityLow` | 1 | bridgevm, oraclevm |
| `PriorityNormal` | 5 | aivm, identityvm |
| `PriorityHigh` | 10 | cevm, dexvm, keyvm |
| `PriorityCritical` | 100 | consensus-blocking work |

## Isolation guarantees

1. **Independent close.** `s.Close()` only releases resources owned by `s`.
   Other VM sessions and the default session continue to operate.
2. **Independent failure.** A panic or error inside `f` passed to `Submit`
   does not corrupt other sessions. The session's failed counter increments;
   the next `Submit` proceeds.
3. **Independent budget.** Memory allocations against one session never count
   against another. Hitting `ErrSessionBudgetExceeded` on one VM does not
   throttle others.

## Ordering guarantee

Within a single `VMSession`, ops complete in the order `Submit` returned to
its caller. The implementation uses a `sync.Mutex` per session as a FIFO
gate; Go's runtime guarantees fair handoff under contention.

Across sessions, no ordering is provided. Two ops submitted to two different
VMs may complete in either order (subject to the underlying backend's
device-side scheduling).

## Memory budget

`WithMemoryBudget(n)` caps the cumulative reserved bytes at `n`. The session
exposes `MemoryUsed()` and ops that allocate use `reserve(n)` / `release(n)`
internally. Exceeding the cap returns `ErrSessionBudgetExceeded`. Set 0 (the
default) for no cap.

## Lifecycle

```
NewVMSession ──► IsAvailable() ──► Submit(...) ──► Close()
                       │
                       └─ false when no GPU backend; Submit returns ErrNoBackends
```

Calling `Close` while a `Submit` is in flight: the close drains the queue by
acquiring the queue lock after marking the session closed. Pending Submit
calls observe `ErrSessionClosed` on the next iteration.

`Close` is idempotent and safe to call from multiple goroutines.

## Default session

`accel.DefaultSession()` still works exactly as before:

- One process-wide session, lazily initialized
- Shared, no isolation, no priority, no budget
- All existing callers (`evmgpu`, `zkvm`, `bridgevm`, `quantumvm`,
  `thresholdvm`, `cevm`) keep working without changes

New code should use `NewVMSession` per VM. Migrate legacy callers when their
ops list grows large enough to compete for GPU time with another VM.

## Test coverage

`multivm_test.go` covers:

- Lifecycle (create, ID, close, double-close)
- Empty-vmID rejection
- Memory budget enforce + release
- 4 VMs × 1000 ops concurrent dispatch with FIFO assertion + tag-based
  cross-contamination check
- Mid-dispatch close of one VM with the other 3 finishing their ops
- Independent close: closing one session leaves others operational
