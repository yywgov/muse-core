package grpcsvc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestFirstTryTimeoutAndKinds(t *testing.T) {
	cases := map[time.Duration]time.Duration{8 * time.Second: 5 * time.Second, 10 * time.Second: 5 * time.Second, 5 * time.Second: 3125 * time.Millisecond, 2 * time.Second: 2 * time.Second}
	for in, want := range cases {
		if got := FirstTryTimeout(in); got != want {
			t.Errorf("FirstTryTimeout(%v) = %v, want %v", in, got, want)
		}
	}
	if resultKind(nil) != resultOK || resultKind(errors.New("connect: connection refused")) != resultFast ||
		resultKind(&net.DNSError{IsNotFound: true}) != resultFast || resultKind(context.DeadlineExceeded) != resultSlow ||
		resultKind(errors.New("timeout")) != resultSlow || resultKind(errors.New("connection reset by peer")) != resultSlow {
		t.Error("result kinds")
	}
	if GateMax(8) != 24 || GateMax(4) != 12 || GateMax(32) != 32 {
		t.Error("GateMax")
	}
}

func TestTestGateAdapts(t *testing.T) {
	g := newTestGate(8)
	for i := 0; i < 8; i++ {
		g.observe(resultOK)
	}
	if g.currentLimit() != 12 {
		t.Fatalf("limit %d after a round without timeouts", g.currentLimit())
	}
	for i := 0; i < 100; i++ {
		g.observe(resultOK)
	}
	if g.currentLimit() != 24 {
		t.Fatalf("limit %d, want 24", g.currentLimit())
	}
	g.observe(resultFast)
	g.observe(resultSlow)
	g.observe(resultSlow)
	if g.currentLimit() != 24 {
		t.Fatal("two timeouts keep the limit")
	}
	g.observe(resultSlow)
	if g.currentLimit() != 8 {
		t.Fatalf("timeouts close together: back to 8, got %d", g.currentLimit())
	}
}

// 穿云 1.10.4: refused = one try, final; a timeout = first try with the short timeout, re-test
// with the full one right after its own failure; 60 nodes run more than 8 at once when none
// times out, never more than 24.
func TestCompatTieredAndAdaptive(t *testing.T) {
	old := RetestAfter
	RetestAfter = 30 * time.Millisecond
	defer func() { RetestAfter = old }()
	s, f := startedWithNodes(t)
	f.mu.Lock()
	f.refuse = map[string]bool{"R": true}
	f.fail = map[string]int{"T": 5}
	f.delay = 20 * time.Millisecond
	f.mu.Unlock()
	var names []string
	for i := 0; i < 60; i++ {
		names = append(names, fmt.Sprintf("n%02d", i))
	}
	s.startTests(append([]string{"R", "T"}, names...))
	waitFor(t, func() bool { return !s.Testing() })
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.timeouts["R"]; len(got) != 1 || got[0] != 5*time.Second {
		t.Errorf("refused: %v, want one try with the first-try timeout", got)
	}
	if got := f.timeouts["T"]; len(got) != 2 || got[0] != 5*time.Second || got[1] != 8*time.Second {
		t.Errorf("timed out: %v, want 5 s then 8 s", got)
	}
	if f.peak <= 8 || f.peak > 24 {
		t.Errorf("peak %d tests at once, want 9–24", f.peak)
	}
}
