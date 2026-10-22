package config

import (
	"testing"
	"time"
)

func TestMuseTestTimeoutClamp(t *testing.T) {
	cases := map[int]time.Duration{0: 0, -5: 0, 500: 2 * time.Second, 6000: 6 * time.Second, 60000: 15 * time.Second}
	for in, want := range cases {
		if got := museTestTimeout(in); got != want {
			t.Fatalf("museTestTimeout(%d) = %v, want %v", in, got, want)
		}
	}
}

func TestMuseSplitHTTPAlias(t *testing.T) {
	in := "vless://id@h:443?type=splithttp&path=%2Fx#a\nvless://id@h:443?security=tls&TYPE=SplitHTTP#b\nvless://id@h:443?type=ws#c"
	want := "vless://id@h:443?type=xhttp&path=%2Fx#a\nvless://id@h:443?security=tls&TYPE=xhttp#b\nvless://id@h:443?type=ws#c"
	if got := string(museSplitHTTPAlias([]byte(in))); got != want {
		t.Fatalf("got %q", got)
	}
}
