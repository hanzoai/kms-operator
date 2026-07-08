// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// nonce_ledger.go — anti-replay ledger for envelope nonces.
//
// The wall-clock freshness window (MaxClockSkew) caps how long a captured
// envelope is replayable, but within the window an attacker who observes
// one valid envelope can resubmit it verbatim. For OpSecretGet that
// produces audit-log churn the attacker controls; for OpSecretPut /
// OpSecretDelete it can be weaponised to obscure a parallel intrusion in
// audit noise or to cancel a legitimate in-flight delete. We close the
// window by ledgering (NodeID, Nonce) on the verifier side and rejecting
// any second sighting before the nonce ages out of the ledger.
//
// Design properties
//
//   - Per-node nonce space. Two distinct signers may reuse the same
//     nonce byte-for-byte without collision; the keying tuple is
//     (NodeID, Nonce). This matches the wire reality: nonces are
//     caller-fresh, not globally coordinated.
//
//   - TTL = MaxClockSkew + 1m. Once an entry has aged past TTL, the
//     clock-skew check would reject any envelope bearing the matching
//     timestamp anyway, so reusing the nonce after TTL is safe and the
//     ledger can GC the entry.
//
//   - First-write-wins. SeenOrInsert returns true (duplicate) for every
//     call after the first within TTL. The first caller wins; the second
//     call sees `seen == true` and the verifier rejects.
//
//   - Race-clean. sync.Map handles the lookup/insert atomically via
//     LoadOrStore. No two goroutines can both observe `seen == false`
//     for the same key.
//
//   - GC budget. A background loop sweeps expired entries every
//     gcInterval (default = TTL/4 = 90s for the default 6m TTL). Inline
//     opportunistic GC is NOT performed in the hot path — the wall-clock
//     check happens earlier and the ledger Insert path stays O(1).
//
// Production sizing (informational, no enforcement)
//
//   100 services × 60 envelopes/min × 6m TTL ≈ 36 000 live entries.
//   sync.Map overhead per entry ≈ 80 bytes (key 36 + value 8 + Go map
//   overhead). Working set ≈ 3 MB. Well within budget for an in-process
//   ledger; no need to fall back to disk-backed storage at this scale.

package envelope

import (
	"context"
	"sync"
	"time"

	"github.com/luxfi/ids"
)

// NonceLedger is the contract the envelope verifier talks to. Production
// impls are typically the in-memory ledger; deployments that need
// cross-process replay defence (e.g. multi-replica kmsd behind a load
// balancer) supply a shared backend.
//
// The contract:
//
//   - SeenOrInsert returns (true, nil) iff (node, nonce) is already
//     recorded as live in the ledger. Returns (false, nil) and atomically
//     records the entry on the first call within TTL.
//
//   - SeenOrInsert MUST be safe for concurrent use. The verifier calls
//     it on every request; a serial impl would bottleneck the surface.
//
//   - SeenOrInsert MUST be deterministic per key: once a key returns
//     (false, nil), every subsequent call within TTL returns (true, nil)
//     until GC ages the entry out.
//
// Errors are reserved for transport failures in disk- or network-backed
// impls. The in-memory ledger never returns an error.
type NonceLedger interface {
	SeenOrInsert(ctx context.Context, node ids.NodeID, nonce string, now time.Time) (bool, error)
}

// DefaultNonceLedgerTTL is the per-entry lifetime. Slightly larger than
// MaxClockSkew so an envelope arriving at the edge of the skew window
// still finds the prior copy in the ledger.
const DefaultNonceLedgerTTL = MaxClockSkew + time.Minute

// DefaultNonceLedgerGCInterval is the sweep cadence for the background
// GC goroutine. Smaller values reduce peak memory but burn CPU; the
// default trades 25% TTL granularity for low-cost sweeps.
const DefaultNonceLedgerGCInterval = DefaultNonceLedgerTTL / 4

// nonceKey is the composite map key. NodeID is 20 bytes; nonce string is
// caller-fresh (typically 16 bytes base64-encoded → 24 chars). Both are
// value types so the struct is map-key safe.
type nonceKey struct {
	node  ids.NodeID
	nonce string
}

// MemoryNonceLedger is the canonical in-process NonceLedger. Backed by
// sync.Map for low-contention concurrent SeenOrInsert.
type MemoryNonceLedger struct {
	ttl        time.Duration
	gcInterval time.Duration

	entries sync.Map // map[nonceKey]time.Time — first-seen wall-clock

	stopCh chan struct{}
	stopMu sync.Mutex
}

// MemoryNonceLedgerConfig wires a MemoryNonceLedger. Zero values pick
// the package defaults (DefaultNonceLedgerTTL, DefaultNonceLedgerGCInterval).
type MemoryNonceLedgerConfig struct {
	// TTL is the per-entry lifetime. 0 → DefaultNonceLedgerTTL.
	TTL time.Duration
	// GCInterval is the background sweep cadence. 0 → DefaultNonceLedgerGCInterval.
	GCInterval time.Duration
}

// NewMemoryNonceLedger returns a fresh in-memory ledger and starts its
// background GC goroutine. Call Stop() at process shutdown to release
// the goroutine. Production callers typically wire one ledger per kmsd
// process and never Stop until the daemon shuts down.
func NewMemoryNonceLedger(cfg MemoryNonceLedgerConfig) *MemoryNonceLedger {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultNonceLedgerTTL
	}
	gc := cfg.GCInterval
	if gc <= 0 {
		gc = DefaultNonceLedgerGCInterval
	}
	l := &MemoryNonceLedger{
		ttl:        ttl,
		gcInterval: gc,
		stopCh:     make(chan struct{}),
	}
	go l.gcLoop()
	return l
}

// SeenOrInsert atomically checks and records (node, nonce). Returns true
// if the key was already present (replay), false if first sighting.
func (l *MemoryNonceLedger) SeenOrInsert(_ context.Context, node ids.NodeID, nonce string, now time.Time) (bool, error) {
	k := nonceKey{node: node, nonce: nonce}
	// LoadOrStore returns (existing, true) if the key was present, or
	// (stored, false) on first insert. Two concurrent inserts race
	// atomically — exactly one returns (_, false).
	prev, loaded := l.entries.LoadOrStore(k, now)
	if !loaded {
		return false, nil
	}
	// A prior entry exists. If it has aged past TTL we treat the slot
	// as expired — the GC just hasn't swept it yet — and overwrite with
	// the new wall-clock. Concurrent overwrites collapse to last-write-
	// wins; either outcome leaves a fresh entry, which is what the
	// caller would have gotten from a clean ledger.
	if prevTS, ok := prev.(time.Time); ok && now.Sub(prevTS) >= l.ttl {
		l.entries.Store(k, now)
		return false, nil
	}
	return true, nil
}

// Size reports the live entry count. Useful for tests + observability.
// Walks the entire map; not a hot-path operation.
func (l *MemoryNonceLedger) Size() int {
	n := 0
	l.entries.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// Stop ends the background GC goroutine. Safe to call multiple times.
func (l *MemoryNonceLedger) Stop() {
	l.stopMu.Lock()
	defer l.stopMu.Unlock()
	select {
	case <-l.stopCh:
		// already stopped
	default:
		close(l.stopCh)
	}
}

// gcLoop sweeps expired entries every gcInterval. Runs until Stop() is
// called. Each sweep is O(n) over the entry map; at 36k entries this is
// microseconds — invisible to the request path.
func (l *MemoryNonceLedger) gcLoop() {
	t := time.NewTicker(l.gcInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case now := <-t.C:
			l.gcOnce(now)
		}
	}
}

// gcOnce is one sweep. Exported via test hook only — production callers
// rely on the background goroutine.
func (l *MemoryNonceLedger) gcOnce(now time.Time) {
	cutoff := now.Add(-l.ttl)
	l.entries.Range(func(k, v any) bool {
		if ts, ok := v.(time.Time); ok && ts.Before(cutoff) {
			// CompareAndDelete protects against a concurrent
			// SeenOrInsert that re-inserted a fresh entry at the
			// same key after we read it: only delete the exact
			// stale value.
			l.entries.CompareAndDelete(k, ts)
		}
		return true
	})
}
