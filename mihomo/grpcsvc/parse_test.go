package grpcsvc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
)

const clashSub = `# my subscription
proxies:
  - {name: HK, type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: pw}
  - {name: Naive, type: naive, server: n.example.com, port: 443}
proxy-groups:
  - {name: 节点选择, type: select, proxies: [HK, Naive]}
rules:
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
`

// M3-4: a subscription is saved exactly as it came (comments, groups, rules, the node this core
// cannot run), and the answer counts usable and unavailable nodes.
func TestParseKeepsBodyAsIs(t *testing.T) {
	s := New(newFake())
	dir := t.TempDir()
	s.Prepare(dir)
	for name, body := range map[string]string{"yaml": clashSub, "links": links} {
		temp := filepath.Join(dir, name+".tmp")
		cfg := filepath.Join(dir, "configs", name+".json")
		if err := os.WriteFile(temp, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := s.Parse(context.Background(), &hcore.ParseRequest{TempPath: temp, ConfigPath: cfg})
		if err != nil || res.ResponseCode != hcommon.ResponseCode_OK {
			t.Fatalf("%s: %v %v", name, res, err)
		}
		got, err := os.ReadFile(cfg)
		if err != nil || string(got) != body {
			t.Fatalf("%s: saved body changed:\n%s", name, got)
		}
		if !strings.Contains(res.Message, "unavailable=1") || !strings.HasPrefix(res.Message, "compat:") {
			t.Fatalf("%s: summary %q", name, res.Message)
		}
	}
}

// An update replaces the saved body only when the new one can be read; a bad download leaves the
// profile as it was (never half written, never emptied).
func TestParseBadBodyKeepsOldProfile(t *testing.T) {
	s := New(newFake())
	dir := t.TempDir()
	cfg := filepath.Join(dir, "p.json")
	if err := os.WriteFile(cfg, []byte(clashSub), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "   \n", "<html>blocked</html>"} {
		temp := filepath.Join(dir, "bad.tmp")
		_ = os.WriteFile(temp, []byte(bad), 0o600)
		res := s.ParseCore(&hcore.ParseRequest{TempPath: temp, ConfigPath: cfg})
		if res.ResponseCode == hcommon.ResponseCode_OK {
			t.Fatalf("%q accepted", bad)
		}
		if got, _ := os.ReadFile(cfg); string(got) != clashSub {
			t.Fatal("old profile touched")
		}
	}
	if res := s.ParseCore(&hcore.ParseRequest{TempPath: filepath.Join(dir, "missing")}); res.ResponseCode == hcommon.ResponseCode_OK {
		t.Fatal("missing temp file accepted")
	}
	if res := s.ParseCore(nil); res.ResponseCode == hcommon.ResponseCode_OK {
		t.Fatal("empty request accepted")
	}
}

// Content without paths: checked and answered unchanged. Config path alone: the full config this
// core would run (secret masked), with the app's routing.
func TestParseContentAndRender(t *testing.T) {
	s := New(newFake())
	dir := t.TempDir()
	s.Prepare(dir)
	res := s.ParseCore(&hcore.ParseRequest{Content: links})
	if res.ResponseCode != hcommon.ResponseCode_OK || res.Content != links {
		t.Fatalf("%v", res)
	}
	settings(t, s, `{"region":"cn","web-secret":"top-secret","route-rule":{"rules":[{"enabled":true,"outbound":"direct","rule_set":["https://x/country/geosite-{region}.srs"]}]}}`)
	cfg := writeProfile(t, dir, clashSub)
	res = s.ParseCore(&hcore.ParseRequest{ConfigPath: cfg})
	if res.ResponseCode != hcommon.ResponseCode_OK {
		t.Fatalf("%v", res)
	}
	for _, want := range []string{"RULE-SET,muse-geosite-cn,DIRECT", "GEOIP,CN,DIRECT", "节点选择"} {
		if !strings.Contains(res.Content, want) {
			t.Fatalf("missing %q in\n%s", want, res.Content)
		}
	}
	if strings.Contains(res.Content, "top-secret") {
		t.Fatal("secret shown")
	}
}

// Start reads a saved Clash YAML body directly: its own groups and rules reach mihomo, the node
// it cannot run is listed as unavailable (kept, not dropped).
func TestStartWithSavedClashBody(t *testing.T) {
	f := newFake()
	f.nodes = map[string]NodeInfo{
		"select": {Name: "select", Group: true, GroupType: "selector", Now: "HK", Members: []string{"HK"}},
		"HK":     {Name: "HK", Type: "Shadowsocks"},
	}
	s := New(f)
	dir := t.TempDir()
	s.Prepare(dir)
	settings(t, s, `{"region":"cn","route-rule":{"rules":[{"list_order":0,"enabled":true,"outbound":"direct","rule_set":["https://x/country/geoip-{region}.srs"]}]}}`)
	cfg := writeProfile(t, dir, clashSub)
	if res := s.StartCore(&hcore.StartRequest{ConfigPath: cfg}); res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("%v", res)
	}
	defer s.StopCore()
	m := f.lastConfig(t)
	rules := m["rules"].([]any)
	if rules[0] != "RULE-SET,muse-geoip-cn,DIRECT" || rules[1] != "GEOIP,CN,DIRECT" {
		t.Fatalf("rules %v", rules)
	}
	u := s.Unsupported()
	if len(u) != 1 || u[0].Name != "Naive" {
		t.Fatalf("unsupported %v", u)
	}
	list := s.GroupList(false)
	var marked bool
	for _, g := range list.Items {
		for _, it := range g.Items {
			if it.Tag == "Naive" && strings.HasPrefix(it.Type, UnsupportedTypePrefix) && !it.IsVisible {
				marked = true
			}
		}
	}
	if !marked {
		t.Fatal("unavailable node not listed and marked")
	}
}
