package sysproxy

import (
	"strings"
	"testing"
)

func TestSystemProxyServerAndBypass(t *testing.T) {
	if got := Server(12334); got != "http://127.0.0.1:12334" {
		t.Fatalf("server %q", got)
	}
	for _, want := range []string{"localhost", "127.*", "10.*", "172.16.*", "172.31.*", "192.168.*", "<local>"} {
		if !strings.Contains(Bypass, want) {
			t.Fatalf("bypass misses %s", want)
		}
	}
}
