package options

import (
	"reflect"
	"strings"
	"testing"

	"github.com/yywgov/muse-core/mihomo/profile"
	"go.yaml.in/yaml/v3"
)

func TestParseSettings(t *testing.T) {
	s, err := ParseSettings("")
	if err != nil || !reflect.DeepEqual(s, Defaults()) {
		t.Fatalf("empty: %+v %v", s, err)
	}
	s, err = ParseSettings(`{"log-level":"debug","clash-api-port":9090,"web-secret":"abc","mixed-port":2080,
		"allow-connection-from-lan":true,"ipv6-mode":"ipv4_only","url-test-interval":300,
		"remote-dns-address":"https://1.1.1.1/dns-query","direct-dns-address":"local","enable-tun":true,
		"tun-implementation":"gvisor","mtu":1500,"strict-route":false,"bypass-lan":true,"unknown-key":{"x":1}}`)
	if err != nil {
		t.Fatal(err)
	}
	if s.LogLevel != "debug" || s.ClashAPIPort != 9090 || s.ClashAPISecret != "abc" || s.MixedPort != 2080 ||
		!s.AllowLAN || s.IPv6Mode != "ipv4_only" || s.TestIntervalSec != 300 || !s.EnableTun ||
		s.TunStack != "gvisor" || s.MTU != 1500 || s.StrictRoute || !s.BypassLAN {
		t.Fatalf("%+v", s)
	}
	// interval as a duration string, missing port falls back
	s, err = ParseSettings(`{"url-test-interval":"120s","mixed-port":0}`)
	if err != nil || s.TestIntervalSec != 120 || s.MixedPort != 12334 {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := ParseSettings(`{not json`); err == nil {
		t.Fatal("bad JSON must fail")
	}
}

func build(t *testing.T, p *profile.Profile, s Settings, rt Runtime) map[string]any {
	t.Helper()
	b, err := Build(p, s, rt)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return m
}

func groupByName(m map[string]any, name string) map[string]any {
	for _, g := range m["proxy-groups"].([]any) {
		gm := g.(map[string]any)
		if gm["name"] == name {
			return gm
		}
	}
	return nil
}

func uriProfile() *profile.Profile {
	return &profile.Profile{Kind: profile.KindURIList, Proxies: []map[string]any{
		{"name": "A", "type": "trojan", "server": "a.example.com", "port": 443, "password": "pw"},
		{"name": "B", "type": "ss", "server": "b.example.com", "port": 8388, "cipher": "aes-128-gcm", "password": "pw"},
	}}
}

func TestBuildURIListDefaults(t *testing.T) {
	m := build(t, uriProfile(), Defaults(), Runtime{ControllerAddr: "127.0.0.1:16756", Secret: "s3"})
	if m["mixed-port"] != 12334 || m["allow-lan"] != false || m["bind-address"] != "127.0.0.1" || m["mode"] != "rule" {
		t.Errorf("inbound: %v %v %v %v", m["mixed-port"], m["allow-lan"], m["bind-address"], m["mode"])
	}
	if m["external-controller"] != "127.0.0.1:16756" || m["secret"] != "s3" || m["log-level"] != "warning" || m["ipv6"] != true {
		t.Errorf("controller/log/ipv6: %v %v %v %v", m["external-controller"], m["secret"], m["log-level"], m["ipv6"])
	}
	if _, ok := m["tun"]; ok {
		t.Error("tun must be absent when disabled")
	}
	sel, auto := groupByName(m, GroupSelect), groupByName(m, GroupAuto)
	if sel == nil || auto == nil {
		t.Fatalf("groups %v", m["proxy-groups"])
	}
	if got := sel["proxies"].([]any); len(got) != 3 || got[0] != GroupAuto || got[1] != "A" || got[2] != "B" {
		t.Errorf("select members %v", got)
	}
	if auto["type"] != "url-test" || auto["url"] != "http://cp.cloudflare.com/" || auto["interval"] != 600 || auto["lazy"] != true {
		t.Errorf("auto %v", auto)
	}
	rules := m["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,"+GroupSelect {
		t.Errorf("rules %v", rules)
	}
	if prof := m["profile"].(map[string]any); prof["store-selected"] != false {
		t.Errorf("profile %v", prof)
	}
}

func TestBuildNoControllerWhenAPIOff(t *testing.T) {
	m := build(t, uriProfile(), Defaults(), Runtime{})
	if _, ok := m["external-controller"]; ok {
		t.Error("no controller expected")
	}
}

func TestBuildSettingsMapping(t *testing.T) {
	s := Defaults()
	s.LogLevel, s.AllowLAN, s.IPv6Mode, s.MixedPort = "trace", true, "ipv4_only", 2080
	s.EnableTun, s.TunStack, s.MTU, s.StrictRoute, s.BypassLAN = true, "system", 1500, false, true
	s.RemoteDNS, s.DirectDNS = "udp://8.8.8.8", "local"
	s.TestURL, s.TestIntervalSec = "https://www.gstatic.com/generate_204", 90
	m := build(t, uriProfile(), s, Runtime{})
	if m["log-level"] != "debug" || m["allow-lan"] != true || m["bind-address"] != "*" || m["ipv6"] != false || m["mixed-port"] != 2080 {
		t.Errorf("general %v %v %v %v %v", m["log-level"], m["allow-lan"], m["bind-address"], m["ipv6"], m["mixed-port"])
	}
	tun := m["tun"].(map[string]any)
	if tun["enable"] != true || tun["stack"] != "system" || tun["mtu"] != 1500 || tun["strict-route"] != false || tun["auto-route"] != true {
		t.Errorf("tun %v", tun)
	}
	dns := m["dns"].(map[string]any)
	if ns := dns["nameserver"].([]any); ns[0] != "8.8.8.8" {
		t.Errorf("nameserver %v", ns)
	}
	if ps := dns["proxy-server-nameserver"].([]any); ps[0] != "223.5.5.5" {
		t.Errorf("proxy-server-nameserver %v", ps)
	}
	auto := groupByName(m, GroupAuto)
	if auto["url"] != "https://www.gstatic.com/generate_204" || auto["interval"] != 90 {
		t.Errorf("auto %v", auto)
	}
	rules := m["rules"].([]any)
	if len(rules) != 5 || !strings.HasPrefix(rules[0].(string), "IP-CIDR,192.168.0.0/16,DIRECT") || rules[4] != "MATCH,select" {
		t.Errorf("rules %v", rules)
	}
	for in, want := range map[string]string{"info": "info", "warn": "warning", "error": "error", "fatal": "error", "": "warning", "silent": "silent"} {
		if got := logLevel(in); got != want {
			t.Errorf("logLevel(%q)=%q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"mixed": "mixed", "gvisor": "gvisor", "system": "system", "": "mixed", "lwip": "mixed"} {
		if got := tunStack(in); got != want {
			t.Errorf("tunStack(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBuildClashYAMLKeepsOwnGroupsAndRules(t *testing.T) {
	p := &profile.Profile{
		Kind:    profile.KindClashYAML,
		Proxies: uriProfile().Proxies,
		Groups:  []map[string]any{{"name": "Proxy", "type": "select", "proxies": []any{"A", "B"}}},
		Rules:   []string{"DOMAIN-SUFFIX,google.com,Proxy", "MATCH,Proxy"},
		Providers: map[string]any{
			"p2": map[string]any{"type": "http", "url": "https://example.com/2", "path": "./p2.yaml"},
			"p1": map[string]any{"type": "http", "url": "https://example.com/1", "path": "./p1.yaml"},
		},
	}
	m := build(t, p, Defaults(), Runtime{})
	groups := m["proxy-groups"].([]any)
	if len(groups) != 3 || groupByName(m, "Proxy") == nil {
		t.Fatalf("groups %v", groups)
	}
	sel := groupByName(m, GroupSelect)
	if got := sel["proxies"].([]any); got[0] != GroupAuto || got[1] != "Proxy" {
		t.Errorf("select should list the profile's groups first: %v", got)
	}
	if use := sel["use"].([]any); len(use) != 2 || use[0] != "p1" || use[1] != "p2" {
		t.Errorf("use %v", use)
	}
	rules := m["rules"].([]any)
	if len(rules) != 2 || rules[1] != "MATCH,Proxy" {
		t.Errorf("rules must keep the profile's MATCH and add none: %v", rules)
	}
	if _, ok := m["proxy-providers"]; !ok {
		t.Error("providers missing")
	}
}

func TestBuildAllUnsupportedFailsClosed(t *testing.T) {
	p := &profile.Profile{Kind: profile.KindURIList, Unsupported: []profile.Unsupported{{Name: "WG", Type: "wireguard", Reason: profile.ReasonUnsupportedProtocol}}}
	m := build(t, p, Defaults(), Runtime{})
	auto := groupByName(m, GroupAuto)
	if got := auto["proxies"].([]any); len(got) != 1 || got[0] != "REJECT" {
		t.Errorf("auto %v", got)
	}
	if _, err := Build(nil, Defaults(), Runtime{}); err == nil {
		t.Error("nil profile must fail")
	}
}

// Windows: the TUN adapter gets the app's name; an Android fd TUN never gets a device name.
func TestBuildTunDevice(t *testing.T) {
	p, err := profile.Parse([]byte("trojan://pw@a.example.com:443#A\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := Defaults()
	s.EnableTun = true
	get := func(rt Runtime) map[string]any {
		buf, err := Build(p, s, rt)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := yaml.Unmarshal(buf, &m); err != nil {
			t.Fatal(err)
		}
		return m["tun"].(map[string]any)
	}
	if tun := get(Runtime{TunDevice: "Chuanyun"}); tun["device"] != "Chuanyun" || tun["auto-route"] != true {
		t.Fatalf("windows tun %v", tun)
	}
	if tun := get(Runtime{}); tun["device"] != nil {
		t.Fatalf("default tun %v", tun)
	}
	if tun := get(Runtime{TunDevice: "Chuanyun", TunFD: 7}); tun["device"] != nil || tun["file-descriptor"] != 7 {
		t.Fatalf("fd tun %v", tun)
	}
}
