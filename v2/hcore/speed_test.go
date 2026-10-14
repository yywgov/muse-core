package hcore

import "testing"

func TestSpeedSince(t *testing.T) {
	if u, d := speedSince(nil, 10, 20); u != 0 || d != 0 {
		t.Fatalf("first sample: %d/%d", u, d)
	}
	prev := &SystemInfo{UplinkTotal: 100, DownlinkTotal: 1000}
	if u, d := speedSince(prev, 150, 3000); u != 50 || d != 2000 {
		t.Fatalf("got %d/%d", u, d)
	}
	// a restarted instance starts from 0 again
	if u, d := speedSince(prev, 5, 7); u != 0 || d != 0 {
		t.Fatalf("after restart: %d/%d", u, d)
	}
}
