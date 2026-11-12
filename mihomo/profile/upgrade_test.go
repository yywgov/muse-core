// 穿云 1.20.5: the compatible core's engine moves from v1.19.33 to v1.19.34 (stable release, patch level).
// These tests pin the version in both places that name it and check what changed for our profiles:
// share links with type=httpupgrade now become the same ws + v2ray-http-upgrade proxy that the
// sing-box JSON mapping (singbox.go) already produced, and the set of proxy types is unchanged.
package profile

import (
	"os"
	"regexp"
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

const pinnedEngine = "v1.19.34"

func TestEnginePinnedInGoModAndWorkflow(t *testing.T) {
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*github\.com/metacubex/mihomo (v\S+)$`).FindSubmatch(mod)
	if m == nil || string(m[1]) != pinnedEngine {
		t.Fatalf("go.mod pins %q, want %s", m, pinnedEngine)
	}
	wf, err := os.ReadFile("../../.github/workflows/mihomo.yml")
	if err != nil {
		t.Fatal(err)
	}
	// the client CI reads this line to stamp constant.Version into the compatible core
	v := regexp.MustCompile(`(?m)^  MIHOMO_VERSION: (\S+)$`).FindSubmatch(wf)
	if v == nil || string(v[1]) != pinnedEngine {
		t.Fatalf("mihomo.yml MIHOMO_VERSION = %q, want %s", v, pinnedEngine)
	}
	// still the protobuf fork the engine itself uses (replace directives are not inherited)
	if !regexp.MustCompile(`(?m)^replace google\.golang\.org/protobuf => github\.com/metacubex/protobuf-go `).Match(mod) {
		t.Fatal("go.mod lost the protobuf replace")
	}
}

func TestURIListHTTPUpgradeLinksMatchSingBoxMapping(t *testing.T) {
	links := "vless://11111111-2222-3333-4444-555555555555@x.example.com:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2Fup#hu-vless\n" +
		"trojan://secret@x.example.com:443?security=tls&type=httpupgrade&host=cdn.example.com&path=%2Fup#hu-trojan\n" +
		"vless://11111111-2222-3333-4444-555555555555@x.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws#ws-vless\n"
	p, err := parseURIList([]byte(links))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Unsupported) != 0 || len(p.Proxies) != 3 {
		t.Fatalf("proxies %d unsupported %v", len(p.Proxies), p.Unsupported)
	}
	for _, px := range p.Proxies {
		name := px["name"].(string)
		if px["network"] != "ws" {
			t.Fatalf("%s: network %v, want ws", name, px["network"])
		}
		ws, _ := px["ws-opts"].(map[string]any)
		_, upgrade := ws["v2ray-http-upgrade"]
		if (name != "ws-vless") != upgrade {
			t.Fatalf("%s: ws-opts %v", name, ws)
		}
		if _, err := adapter.ParseProxy(px); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestSupportedTypesStillParse(t *testing.T) {
	// every type we keep must still be known to the engine: a minimal proxy of an unknown type
	// fails with "unsupport proxy type", anything else (missing fields) means the type exists
	for typ := range supportedTypes {
		_, err := adapter.ParseProxy(map[string]any{"name": "t", "type": typ})
		if err != nil && regexp.MustCompile(`(?i)unsupport proxy type`).MatchString(err.Error()) {
			t.Fatalf("type %q no longer supported: %v", typ, err)
		}
	}
}
