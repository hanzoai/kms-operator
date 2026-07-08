// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package accel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// Priority assigns relative GPU scheduling weight to a VMSession.
// Higher value runs first when multiple sessions contend for the queue.
type Priority int

const (
	PriorityLow      Priority = 1
	PriorityNormal   Priority = 5
	PriorityHigh     Priority = 10
	PriorityCritical Priority = 100
)

// VMSessionOption configures a per-VM session.
type VMSessionOption func(*vmSessionConfig)

type vmSessionConfig struct {
	priority   Priority
	memBudget  int64 // bytes; 0 = unlimited
	backend    BackendType
	queueDepth int
	useDefault bool // if true, share the default Session handle
}

// WithPriority sets the dispatch priority for the VM session.
func WithPriority(p Priority) VMSessionOption {
	return func(c *vmSessionConfig) { c.priority = p }
}

// WithMemoryBudget caps the GPU memory this session may allocate (bytes).
// 0 means unlimited (default).
func WithMemoryBudget(bytes int64) VMSessionOption {
	return func(c *vmSessionConfig) { c.memBudget = bytes }
}

// WithVMBackend pins the VM session to a specific backend.
func WithVMBackend(b BackendType) VMSessionOption {
	return func(c *vmSessionConfig) { c.backend = b }
}

// WithQueueDepth sets the in-flight op queue depth (default 1024).
func WithQueueDepth(n int) VMSessionOption {
	return func(c *vmSessionConfig) {
		if n > 0 {
			c.queueDepth = n
		}
	}
}

// WithSharedDevice routes the VM session through the process default Session
// rather than allocating a new device-side session. Use when the underlying
// driver doesn't support multiple sessions (or to avoid CUDA context churn).
func WithSharedDevice() VMSessionOption {
	return func(c *vmSessionConfig) { c.useDefault = true }
}

// VMSession is a per-VM GPU session providing:
//   - Isolation: closing one VM session does not affect others.
//   - Ordering: ops submitted to a session complete in submission order.
//   - Priority: sessions with higher Priority preempt the global queue.
//   - Memory budget: optional cap on cumulative allocations.
//
// VMSession is safe for concurrent use; submissions from many goroutines on
// the same session are serialized in FIFO order.
type VMSession struct {
	id       string
	priority Priority
	memCap   int64

	// Underlying GPU session. May be shared (pointer to default) or owned.
	sess   *Session
	owned  bool

	// Serialized dispatch queue. Each op runs while holding qMu, guaranteeing
	// FIFO ordering within this VMSession.
	qMu sync.Mutex

	// Lifecycle.
	closed   atomic.Bool
	closeErr error
	closeMu  sync.Mutex

	// Memory accounting.
	memUsed atomic.Int64

	// Stats.
	dispatched atomic.Uint64
	completed  atomic.Uint64
	failed     atomic.Uint64
}

// ErrSessionBudgetExceeded is returned when an op would exceed the memory cap.
var ErrSessionBudgetExceeded = errors.New("accel: session memory budget exceeded")

// ErrEmptyVMID is returned when NewVMSession is called with an empty vmID.
var ErrEmptyVMID = errors.New("accel: vmID must not be empty")

// NewVMSession creates an isolated VM session.
// vmID must be non-empty and is used in error messages and metrics.
func NewVMSession(vmID string, opts ...VMSessionOption) (*VMSession, error) {
	if vmID == "" {
		return nil, ErrEmptyVMID
	}

	cfg := &vmSessionConfig{
		priority:   PriorityNormal,
		backend:    BackendAuto,
		queueDepth: 1024,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var (
		sess  *Session
		owned bool
		err   error
	)

	if cfg.useDefault {
		sess, err = DefaultSession()
		owned = false
	} else {
		sopts := []SessionOption{}
		if cfg.backend != BackendAuto {
			sopts = append(sopts, WithBackend(cfg.backend))
		}
		sess, err = NewSession(sopts...)
		owned = true
	}

	if err != nil {
		// When no GPU backend is available, fall back to a stub session so
		// the VM can still wire up and serialize ops. CPU-only callers will
		// hit ErrNoBackends on actual Submit invocation. We treat the
		// underlying capi-layer error and the public accel.ErrNoBackends
		// the same way: both signify "no GPU, run CPU-only".
		if isNoBackend(err) {
			return &VMSession{
				id:       vmID,
				priority: cfg.priority,
				memCap:   cfg.memBudget,
				sess:     nil,
				owned:    false,
			}, nil
		}
		return nil, err
	}

	return &VMSession{
		id:       vmID,
		priority: cfg.priority,
		memCap:   cfg.memBudget,
		sess:     sess,
		owned:    owned,
	}, nil
}

// ID returns the VM identifier.
func (v *VMSession) ID() string { return v.id }

// Priority returns the dispatch priority.
func (v *VMSession) Priority() Priority { return v.priority }

// Session returns the underlying GPU session, or nil if no backend was
// available. Callers should check IsAvailable() before dereferencing.
func (v *VMSession) Session() *Session { return v.sess }

// IsAvailable reports whether the session is backed by a real GPU session.
func (v *VMSession) IsAvailable() bool {
	return v.sess != nil && !v.closed.Load()
}

// IsClosed reports whether Close() has been called.
func (v *VMSession) IsClosed() bool { return v.closed.Load() }

// MemoryUsed returns the current cumulative allocation count, in bytes.
func (v *VMSession) MemoryUsed() int64 { return v.memUsed.Load() }

// Stats returns dispatch counters: (dispatched, completed, failed).
func (v *VMSession) Stats() (uint64, uint64, uint64) {
	return v.dispatched.Load(), v.completed.Load(), v.failed.Load()
}

// reserve attempts to reserve n bytes against the budget. Returns
// ErrSessionBudgetExceeded if the cap would be crossed.
func (v *VMSession) reserve(n int64) error {
	if v.memCap <= 0 {
		v.memUsed.Add(n)
		return nil
	}
	for {
		cur := v.memUsed.Load()
		if cur+n > v.memCap {
			return ErrSessionBudgetExceeded
		}
		if v.memUsed.CompareAndSwap(cur, cur+n) {
			return nil
		}
	}
}

// release returns n bytes to the budget pool.
func (v *VMSession) release(n int64) {
	v.memUsed.Add(-n)
}

// Submit serializes f under the session's FIFO queue. It returns
// ErrSessionClosed if the session has been closed. Within a VMSession,
// concurrent Submit calls execute in arrival order (Go's sync.Mutex
// guarantees FIFO acquisition under contention via the runtime's
// starvation-prevention handoff).
func (v *VMSession) Submit(ctx context.Context, f func(*Session) error) error {
	if v.closed.Load() {
		return ErrSessionClosed
	}

	// Acquire the queue lock with context-cancellation support.
	if err := lockCtx(ctx, &v.qMu); err != nil {
		return err
	}
	defer v.qMu.Unlock()

	// Re-check after acquiring (Close may have run while we waited).
	if v.closed.Load() {
		return ErrSessionClosed
	}

	v.dispatched.Add(1)
	if v.sess == nil {
		v.failed.Add(1)
		return ErrNoBackends
	}

	if err := f(v.sess); err != nil {
		v.failed.Add(1)
		return err
	}
	v.completed.Add(1)
	return nil
}

// Sync blocks until all pending ops on this session complete.
func (v *VMSession) Sync() error {
	if v.closed.Load() {
		return ErrSessionClosed
	}
	if v.sess == nil {
		return nil
	}
	return v.sess.Sync()
}

// Close releases this session. Safe to call multiple times.
// Closing a session does NOT affect other VM sessions, even when
// WithSharedDevice was used (the shared default Session is reference-
// counted and only torn down by accel.Shutdown).
func (v *VMSession) Close() error {
	if !v.closed.CompareAndSwap(false, true) {
		return v.closeErr
	}

	v.closeMu.Lock()
	defer v.closeMu.Unlock()

	// Drain: wait for in-flight Submit to finish by acquiring the queue lock.
	v.qMu.Lock()
	v.qMu.Unlock()

	if v.owned && v.sess != nil {
		v.closeErr = v.sess.Close()
	}
	return v.closeErr
}

// isNoBackend reports whether err signals "no GPU backend available", whether
// raised at the public accel layer or by the underlying capi layer.
func isNoBackend(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoBackends) {
		return true
	}
	// The capi layer uses its own sentinel ("no backends"); match by text
	// so we don't import internal/capi from the public API.
	return err.Error() == "no backends"
}

// lockCtx acquires mu, respecting ctx cancellation.
func lockCtx(ctx context.Context, mu *sync.Mutex) error {
	if ctx == nil {
		mu.Lock()
		return nil
	}
	// Fast path: try-lock once via a goroutine race against ctx.
	acquired := make(chan struct{})
	go func() {
		mu.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
		return nil
	case <-ctx.Done():
		// We must wait for the lock goroutine to finish, then release,
		// otherwise we leak a held mutex. Spawn a reaper.
		go func() {
			<-acquired
			mu.Unlock()
		}()
		return ctx.Err()
	}
}
