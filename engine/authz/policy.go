package authz

import "sync/atomic"

// PolicyHolder holds a *Policy behind an atomic pointer, enabling lock-free
// reads from any goroutine and safe swaps by a single writer (the gateway's
// reload path). The hot path is: h.Get() once at entry, use the snapshot
// for the lifetime of the request. This means a reload that happens mid-request
// does not affect that in-flight request; the next request sees the new policy.
type PolicyHolder struct {
	ptr atomic.Pointer[Policy]
}

// NewPolicyHolder constructs a PolicyHolder pre-loaded with the given policy.
// p may be nil (passthrough/dev mode).
func NewPolicyHolder(p *Policy) *PolicyHolder {
	h := &PolicyHolder{}
	if p != nil {
		h.ptr.Store(p)
	}
	return h
}

// Get returns the current policy snapshot. The returned pointer must not be
// stored beyond the current request's lifetime; callers should re-call Get()
// on each new request to pick up reloads.
func (h *PolicyHolder) Get() *Policy {
	return h.ptr.Load()
}

// Set atomically replaces the stored policy. Safe to call concurrently with
// Get from any number of goroutines. Passing nil effectively re-enables
// passthrough mode.
func (h *PolicyHolder) Set(p *Policy) {
	h.ptr.Store(p)
}
