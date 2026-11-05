package config

import (
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// 穿云 1.10.4: the same node listed twice (another name) is tested once; a node that differs in
// anything (here the password or the port) is tested on its own.
func TestMuseSameAsIdenticalNodes(t *testing.T) {
	const profile = `{"outbounds": [
    {"type": "socks", "tag": "A", "server": "198.51.100.7", "server_port": 1080, "password": "x"},
    {"type": "socks", "tag": "A (sub 2)", "server": "198.51.100.7", "server_port": 1080, "password": "x"},
    {"type": "socks", "tag": "A other user", "server": "198.51.100.7", "server_port": 1080, "password": "y"},
    {"type": "socks", "tag": "A other port", "server": "198.51.100.7", "server_port": 1081, "password": "x"},
    {"type": "socks", "tag": "A third copy", "server": "198.51.100.7", "server_port": 1080, "password": "x"}
  ]}`
	options, err := BuildConfig(libbox.BaseContext(nil), DefaultHiddifyOptions(), &ReadOptions{Content: profile})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	same := options.Experimental.Monitoring.MuseSameAs
	want := map[string]string{"A (sub 2)": "A", "A third copy": "A"}
	if len(same) != len(want) {
		t.Fatalf("MuseSameAs = %v, want %v", same, want)
	}
	for k, v := range want {
		if same[k] != v {
			t.Fatalf("MuseSameAs = %v, want %v", same, want)
		}
	}
	// groups and built-in outbounds never share
	for k := range same {
		for _, out := range options.Outbounds {
			if out.Tag == k && (out.Type == "selector" || out.Type == "urltest" || out.Type == "direct") {
				t.Fatalf("group %q in MuseSameAs", k)
			}
		}
	}
}

func TestMuseSameAsNone(t *testing.T) {
	if got := museSameAs(libbox.BaseContext(nil), nil); got != nil {
		t.Fatalf("got %v", got)
	}
}
