package grpcsvc

// 穿云 1.10.4: 测速 of the compatible core, the same rules as the main core's (patch 0013):
// tiered timeouts, fast failures final at once, adaptive number of tests at once.

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	firstTryMin    = 3 * time.Second
	firstTryMax    = 5 * time.Second
	gateCeiling    = 24
	gateStep       = 4
	gateWindow     = 8
	gateSlowToDrop = 3
)

// FirstTryTimeout is the timeout of a node's first try: 5/8 of the full one, 3–5 s.
func FirstTryTimeout(full time.Duration) time.Duration {
	t := full * 5 / 8
	if t < firstTryMin {
		t = firstTryMin
	}
	if t > firstTryMax {
		t = firstTryMax
	}
	if t > full {
		t = full
	}
	return t
}

type resultKindT int

const (
	resultOK resultKindT = iota
	resultFast
	resultSlow
)

// fastFailure: the node cannot answer, with no packet loss involved (refused, no such host).
func fastFailure(err error) bool {
	if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	m := strings.ToLower(err.Error())
	if strings.Contains(m, "timeout") || strings.Contains(m, "deadline") {
		return false
	}
	return strings.Contains(m, "connection refused") || strings.Contains(m, "no such host") || strings.Contains(m, "nxdomain")
}

func resultKind(err error) resultKindT {
	switch {
	case err == nil:
		return resultOK
	case fastFailure(err):
		return resultFast
	default:
		return resultSlow
	}
}

// GateMax is the most tests at once the gate grows to from [base].
func GateMax(base int) int {
	m := base * 3
	if m > gateCeiling {
		m = gateCeiling
	}
	if m < base {
		m = base
	}
	return m
}

// testGate limits the tests running at once: +4 after a round without a timeout (up to GateMax),
// back to the configured count after several timeouts close together.
type testGate struct {
	mu     sync.Mutex
	base   int
	max    int
	limit  int
	inUse  int
	peak   int
	streak int
	recent []bool
	wake   chan struct{}
}

func newTestGate(base int) *testGate {
	return &testGate{base: base, max: GateMax(base), limit: base, wake: make(chan struct{})}
}

func (g *testGate) acquire() {
	for {
		g.mu.Lock()
		if g.inUse < g.limit {
			g.inUse++
			if g.inUse > g.peak {
				g.peak = g.inUse
			}
			g.mu.Unlock()
			return
		}
		wake := g.wake
		g.mu.Unlock()
		<-wake
	}
}

func (g *testGate) release(kind resultKindT) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inUse--
	g.observe(kind)
	close(g.wake)
	g.wake = make(chan struct{})
}

func (g *testGate) observe(kind resultKindT) {
	slow := kind == resultSlow
	g.recent = append(g.recent, slow)
	if len(g.recent) > gateWindow {
		g.recent = g.recent[len(g.recent)-gateWindow:]
	}
	if slow {
		g.streak = 0
		n := 0
		for _, s := range g.recent {
			if s {
				n++
			}
		}
		if n >= gateSlowToDrop && g.limit > g.base {
			g.limit, g.recent = g.base, nil
		}
		return
	}
	g.streak++
	if g.streak >= g.limit && g.limit < g.max {
		g.limit += gateStep
		if g.limit > g.max {
			g.limit = g.max
		}
		g.streak = 0
	}
}

func (g *testGate) currentLimit() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limit
}
