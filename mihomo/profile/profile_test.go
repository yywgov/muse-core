package profile

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const clashYAML = `
mixed-port: 7890
proxies:
  - {name: HK-ss, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: pw}
  - {name: JP-vless, type: vless, server: jp.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, servername: jp.example.com}
  - {name: US-naive, type: naive, server: us.example.com, port: 443}
  - {name: TS, type: tailscale}
  - {type: trojan, server: x, port: 1}
  - just-a-string
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK-ss, JP-vless, US-naive]}
  - {name: Only-naive, type: select, proxies: [US-naive, TS]}
  - {name: Prov, type: select, use: [p1], proxies: [US-naive]}
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN,naive.example.com,US-naive
  - DOMAIN,ts.example.com,TS,no-resolve
  - MATCH,Proxy
proxy-providers:
  p1: {type: http, url: "https://example.com/p1.yaml", interval: 3600, path: ./p1.yaml}
`

func unsupportedBy(p *Profile) map[string]Unsupported {
	m := map[string]Unsupported{}
	for _, u := range p.Unsupported {
		m[u.Name] = u
	}
	return m
}

func TestClashYAMLKeepsSupportedAndMarksTheRest(t *testing.T) {
	p, err := Parse([]byte(clashYAML))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindClashYAML {
		t.Fatalf("kind %v", p.Kind)
	}
	if len(p.Proxies) != 2 || p.Proxies[0]["name"] != "HK-ss" || p.Proxies[1]["name"] != "JP-vless" {
		t.Fatalf("proxies %v", p.Proxies)
	}
	u := unsupportedBy(p)
	if len(p.Unsupported) != 4 {
		t.Fatalf("unsupported %v", p.Unsupported)
	}
	if u["US-naive"].Reason != ReasonUnsupportedProtocol || u["US-naive"].Type != "naive" {
		t.Errorf("naive: %+v", u["US-naive"])
	}
	if u["TS"].Reason != ReasonNotBuilt {
		t.Errorf("tailscale: %+v", u["TS"])
	}
	if u["#5"].Reason != ReasonInvalid || u["#6"].Reason != ReasonInvalid {
		t.Errorf("invalid entries: %+v", p.Unsupported)
	}
	if len(p.Groups) != 3 || len(p.Rules) != 4 || len(p.Providers) != 1 {
		t.Fatalf("groups %d rules %d providers %d", len(p.Groups), len(p.Rules), len(p.Providers))
	}
}

func TestClashYAMLDropsReferencesFailClosed(t *testing.T) {
	p, err := Parse([]byte(clashYAML))
	if err != nil {
		t.Fatal(err)
	}
	members := func(i int) []any { return p.Groups[i]["proxies"].([]any) }
	if got := members(0); len(got) != 2 || got[0] != "HK-ss" || got[1] != "JP-vless" {
		t.Errorf("Proxy group %v", got)
	}
	if got := members(1); len(got) != 1 || got[0] != "REJECT" {
		t.Errorf("emptied group must fall back to REJECT, got %v", got)
	}
	if got := members(2); len(got) != 0 {
		t.Errorf("group with a provider stays empty (provider fills it), got %v", got)
	}
	want := []string{"DOMAIN-SUFFIX,google.com,Proxy", "DOMAIN,naive.example.com,REJECT", "DOMAIN,ts.example.com,REJECT,no-resolve", "MATCH,Proxy"}
	for i, r := range want {
		if p.Rules[i] != r {
			t.Errorf("rule %d = %q, want %q", i, p.Rules[i], r)
		}
	}
}

func TestURIListBase64(t *testing.T) {
	links := strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?encryption=none&security=tls&sni=a.example.com&type=ws&path=%2Fws#A%20node",
		"trojan://pw@b.example.com:443?sni=b.example.com#B",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@c.example.com:8388#C",
		"hysteria2://pw@d.example.com:443?sni=d.example.com#D",
		"tuic://11111111-2222-3333-4444-555555555555:pw@e.example.com:443?congestion_control=bbr&alpn=h3#E",
		"wireguard://key@f.example.com:51820?publickey=abc#WG",
		"naive+https://user:pw@g.example.com:443#Naive",
		"ssh://root@h.example.com:22#SSH",
		"trojan://pw@b.example.com:443#B",
		"",
		"# comment line",
	}, "\n")
	p, err := Parse([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindURIList {
		t.Fatalf("kind %v", p.Kind)
	}
	var names []string
	for _, px := range p.Proxies {
		names = append(names, px["name"].(string))
	}
	want := []string{"A node", "B", "C", "D", "E", "B-01"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("names %v want %v", names, want)
	}
	types := map[string]string{}
	for _, px := range p.Proxies {
		types[px["name"].(string)] = px["type"].(string)
	}
	if types["A node"] != "vless" || types["C"] != "ss" || types["D"] != "hysteria2" || types["E"] != "tuic" {
		t.Errorf("types %v", types)
	}
	u := unsupportedBy(p)
	for _, n := range []string{"WG", "Naive", "SSH"} {
		if u[n].Reason != ReasonUnsupportedProtocol {
			t.Errorf("%s should be marked unsupported, got %+v", n, u[n])
		}
	}
	if u["Naive"].Type != "naive+https" {
		t.Errorf("naive type %q", u["Naive"].Type)
	}
}

func TestURIListPlainAndInvalid(t *testing.T) {
	p, err := Parse([]byte("vmess://not-base64-json\ntrojan://pw@x.example.com:443#X\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Proxies) != 1 || p.Proxies[0]["name"] != "X" {
		t.Fatalf("proxies %v", p.Proxies)
	}
	if len(p.Unsupported) != 1 || p.Unsupported[0].Reason != ReasonInvalid || p.Unsupported[0].Type != "vmess" {
		t.Fatalf("unsupported %+v", p.Unsupported)
	}
}

func TestOtherFormats(t *testing.T) {
	if _, err := Parse([]byte(` {"outbounds":[{"type":"selector","tag":"select"}]}`)); !errors.Is(err, ErrEmpty) {
		t.Errorf("groups only: %v", err)
	}
	if _, err := Parse([]byte(`{bad json`)); err == nil {
		t.Error("bad JSON must fail")
	}
	if _, err := Parse([]byte("\xef\xbb\xbf  \n")); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty: %v", err)
	}
	if _, err := Parse([]byte("hello world\nno links here")); !errors.Is(err, ErrEmpty) {
		t.Errorf("no links: %v", err)
	}
	if _, err := Parse([]byte("proxies: []\n")); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty YAML: %v", err)
	}
}

func TestReject(t *testing.T) {
	p, err := Parse([]byte(clashYAML))
	if err != nil {
		t.Fatal(err)
	}
	if p.Reject(5, "x") || p.Reject(-1, "x") {
		t.Fatal("out of range must report false")
	}
	if !p.Reject(0, "bad cipher") {
		t.Fatal("reject 0")
	}
	if len(p.Proxies) != 1 || p.Proxies[0]["name"] != "JP-vless" {
		t.Fatalf("proxies %v", p.Proxies)
	}
	u := unsupportedBy(p)["HK-ss"]
	if u.Reason != ReasonInvalid || u.Detail != "bad cipher" || u.Type != "ss" {
		t.Fatalf("%+v", u)
	}
	if got := p.Groups[0]["proxies"].([]any); len(got) != 1 || got[0] != "JP-vless" {
		t.Errorf("group %v", got)
	}
}

func TestSupportedTypesExcludeTrimmed(t *testing.T) {
	for typ := range trimmedTypes {
		if SupportedType(typ) {
			t.Errorf("%s is left out of the build but listed as supported", typ)
		}
		if !strings.Contains(BuildTags, "no_"+typ) {
			t.Errorf("BuildTags %q must carry no_%s", BuildTags, typ)
		}
	}
	for _, typ := range []string{"vless", "vmess", "trojan", "ss", "hysteria2", "tuic", "anytls", "wireguard", "VLESS"} {
		if !SupportedType(typ) {
			t.Errorf("%s should be supported", typ)
		}
	}
}
