package options

import (
	"reflect"
	"strings"
	"testing"

	"github.com/yywgov/muse-core/mihomo/profile"
)

const geo = "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set"

// The app's default list (局域网, 去广告, 国内直连) as the client sends it: proto3 JSON names,
// enums by name, the default outbound (proxy) left out.
var defaultRouteRule = `{"rules":[
 {"list_order":0,"enabled":true,"name":"builtin:bypassLan","outbound":"direct","ip_cidr":["10.0.0.0/8","192.168.0.0/16","fc00::/7"]},
 {"list_order":1,"enabled":true,"name":"builtin:blockAds","outbound":"block","rule_set":["` + geo + `/block/geosite-category-ads-all.srs","` + geo + `/block/geoip-malware.srs"]},
 {"list_order":2,"enabled":true,"name":"builtin:bypassRegion","outbound":"direct","rule_set":["` + geo + `/country/geosite-{region}.srs","` + geo + `/country/geoip-{region}.srs"]}
]}`

func settingsWith(t *testing.T, js string) Settings {
	t.Helper()
	s, err := ParseSettings(js)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMapRuleSet(t *testing.T) {
	cases := []struct {
		url, region string
		ok          bool
		want        RuleProvider
	}{
		{geo + "/country/geosite-{region}.srs", "cn", true, RuleProvider{"muse-geosite-cn", "domain", GeoDataBase + "geosite/cn.mrs"}},
		{geo + "/country/geoip-{region}.srs", "CN", true, RuleProvider{"muse-geoip-cn", "ipcidr", GeoDataBase + "geoip/cn.mrs"}},
		{"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-youtube.srs?x=1", "", true, RuleProvider{"muse-geosite-youtube", "domain", GeoDataBase + "geosite/youtube.mrs"}},
		{geo + "/country/geoip-{region}.srs", "other", false, RuleProvider{}},
		{geo + "/country/geoip-{region}.srs", "", false, RuleProvider{}},
		{"https://example.com/list.txt", "cn", false, RuleProvider{}},
		{"https://example.com/my-rules.srs", "cn", false, RuleProvider{}},
	}
	for _, c := range cases {
		got, ok := MapRuleSet(c.url, c.region)
		if ok != c.ok || got != c.want {
			t.Errorf("%s (%s): %+v %v", c.url, c.region, got, ok)
		}
	}
}

// 规则 mode with region cn: mainland lists go direct, in the app's order, before the profile's own rules.
func TestDefaultRulesMainlandDirect(t *testing.T) {
	s := settingsWith(t, `{"region":"cn","direct-dns-address":"udp://223.5.5.5","remote-dns-address":"udp://1.1.1.1","route-rule":`+defaultRouteRule+`}`)
	p := &profile.Profile{Proxies: []map[string]any{{"name": "A", "type": "trojan", "server": "a.example.com", "port": 443, "password": "x"}},
		Rules: []string{"DOMAIN-SUFFIX,google.com,select"}}
	m := build(t, p, s, Runtime{})
	rules := toStrings(m["rules"])
	want := []string{
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR6,fc00::/7,DIRECT,no-resolve",
		"RULE-SET,muse-geosite-category-ads-all,REJECT",
		"RULE-SET,muse-geoip-malware,REJECT",
		"RULE-SET,muse-geosite-cn,DIRECT",
		"RULE-SET,muse-geoip-cn,DIRECT",
		"DOMAIN-SUFFIX,google.com,select",
		"MATCH,select",
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules:\n%s", strings.Join(rules, "\n"))
	}
	rp := m["rule-providers"].(map[string]any)
	cn := rp["muse-geosite-cn"].(map[string]any)
	if cn["type"] != "http" || cn["format"] != "mrs" || cn["behavior"] != "domain" || cn["url"] != GeoDataBase+"geosite/cn.mrs" ||
		cn["proxy"] != GroupSelect || cn["interval"] != RuleSetInterval || cn["path"] != "./ruleset/muse-geosite-cn.mrs" {
		t.Fatalf("provider %v", cn)
	}
	if ip := rp["muse-geoip-cn"].(map[string]any); ip["behavior"] != "ipcidr" {
		t.Fatalf("geoip provider %v", ip)
	}
	// DNS: mainland domains by the direct DNS (always straight out), the rest by the remote DNS following the rules
	dns := m["dns"].(map[string]any)
	if dns["respect-rules"] != true || !reflect.DeepEqual(toStrings(dns["nameserver"]), []string{"1.1.1.1"}) ||
		!reflect.DeepEqual(toStrings(dns["proxy-server-nameserver"]), []string{"223.5.5.5"}) ||
		!reflect.DeepEqual(toStrings(dns["direct-nameserver"]), []string{"223.5.5.5#DIRECT"}) {
		t.Fatalf("dns %v", dns)
	}
	policy := dns["nameserver-policy"].(map[string]any)
	if !reflect.DeepEqual(toStrings(policy["rule-set:muse-geosite-cn"]), []string{"223.5.5.5#DIRECT"}) {
		t.Fatalf("policy %v", policy)
	}
	if _, ok := policy["rule-set:muse-geosite-category-ads-all"]; ok {
		t.Fatal("a block list is not a direct-DNS list")
	}
	if m["find-process-mode"] != "off" {
		t.Fatal("no app rule: process lookup stays off")
	}
}

// 全局 mode: the app sends the list without its direct rules (局域网 kept); nothing mainland goes direct.
func TestGlobalModeListHasNoMainlandDirect(t *testing.T) {
	global := `{"rules":[{"list_order":0,"enabled":true,"name":"builtin:bypassLan","outbound":"direct","ip_cidr":["10.0.0.0/8"]}]}`
	s := settingsWith(t, `{"region":"cn","route-rule":`+global+`}`)
	m := build(t, &profile.Profile{Proxies: []map[string]any{{"name": "A", "type": "socks5", "server": "x", "port": 1}}}, s, Runtime{})
	rules := toStrings(m["rules"])
	if !reflect.DeepEqual(rules, []string{"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "MATCH,select"}) {
		t.Fatalf("%v", rules)
	}
	if _, ok := m["rule-providers"]; ok {
		t.Fatal("no list needed")
	}
	if _, ok := m["dns"].(map[string]any)["nameserver-policy"]; ok {
		t.Fatal("no direct-DNS policy in 全局")
	}
}

// region other: the region rule needs a region and is dropped, not turned into match-all.
func TestRegionOtherDropsRegionRule(t *testing.T) {
	plan := PlanRoutes(mustRR(t, defaultRouteRule), "other")
	for _, r := range plan.Rules {
		if strings.Contains(r, "-cn") || r == "DIRECT" {
			t.Fatalf("region rule kept: %v", plan.Rules)
		}
	}
	if len(plan.Rules) != 5 {
		t.Fatalf("%v", plan.Rules)
	}
}

func TestUserRulesAndQualifiers(t *testing.T) {
	rr := mustRR(t, `{"rules":[
	 {"list_order":5,"enabled":true,"name":"later","outbound":1,"domain":["late.example"]},
	 {"list_order":1,"enabled":true,"name":"proxy-these","domain_suffix":[".openai.com"],"domain_keyword":["chatgpt"],"domain":["x.ai"]},
	 {"list_order":2,"enabled":true,"name":"udp-games","outbound":"direct","network":"udp","port_range":["27015:27050","3478"],"domain_suffix":["steam.example"]},
	 {"list_order":3,"enabled":true,"name":"apps","outbound":"direct","package_name":["com.tencent.mm"],"process_name":["WeChat.exe"]},
	 {"list_order":4,"enabled":true,"name":"quic","outbound":"block","protocol":["quic"]},
	 {"list_order":6,"enabled":false,"name":"off","outbound":"direct","domain":["off.example"]},
	 {"list_order":7,"enabled":true,"name":"bt","outbound":"block","protocol":["bittorrent"]},
	 {"list_order":8,"enabled":true,"name":"unmapped","outbound":"direct","rule_set":["https://example.com/custom.srs"]},
	 {"list_order":9,"enabled":true,"name":"regex","outbound":"direct","domain_regex":["^a\\.(b|c)$"]}
	]}`)
	plan := PlanRoutes(rr, "cn")
	want := []string{
		"DOMAIN,x.ai,select",
		"DOMAIN-SUFFIX,openai.com,select",
		"DOMAIN-KEYWORD,chatgpt,select",
		"AND,((DOMAIN-SUFFIX,steam.example),(NETWORK,UDP),(DST-PORT,27015-27050/3478)),DIRECT",
		"OR,((PROCESS-NAME,WeChat.exe),(PROCESS-NAME,com.tencent.mm)),DIRECT",
		"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
		"DOMAIN,late.example,DIRECT",
		`DOMAIN-REGEX,^a\.(b|c)$,DIRECT`,
	}
	if !reflect.DeepEqual(plan.Rules, want) {
		t.Fatalf("rules:\n%s", strings.Join(plan.Rules, "\n"))
	}
	if !plan.Process {
		t.Fatal("app rule needs process lookup")
	}
	// only a plain direct rule names direct-DNS domains (not one limited to UDP / ports)
	if !reflect.DeepEqual(plan.DirectDNS, []string{"late.example"}) {
		t.Fatalf("dns %v", plan.DirectDNS)
	}
	if len(plan.Skipped) != 2 {
		t.Fatalf("skipped %v", plan.Skipped)
	}
	m := build(t, &profile.Profile{Proxies: []map[string]any{{"name": "A", "type": "socks5", "server": "x", "port": 1}}},
		settingsWith(t, `{"route-rule":{"rules":[{"enabled":true,"outbound":"direct","process_name":["a.exe"]}]}}`), Runtime{})
	if m["find-process-mode"] != "strict" {
		t.Fatal("process lookup on for app rules")
	}
}

// A list this core cannot read never fails the settings or the start: it maps to nothing.
func TestBadRouteRuleIgnored(t *testing.T) {
	s := settingsWith(t, `{"route-rule":"not an object","region":"cn"}`)
	if _, err := s.Routes(); err == nil {
		t.Fatal("expected a route-rule error")
	}
	m := build(t, &profile.Profile{Proxies: []map[string]any{{"name": "A", "type": "socks5", "server": "x", "port": 1}}}, s, Runtime{})
	if !reflect.DeepEqual(toStrings(m["rules"]), []string{"MATCH,select"}) {
		t.Fatalf("%v", m["rules"])
	}
}

func TestPortPayload(t *testing.T) {
	if got := portPayload([]string{"443", "1000:2000", ":80", "8000:", "bad", "70000"}); got != "443/1000-2000/0-80/8000-65535" {
		t.Fatal(got)
	}
}

func mustRR(t *testing.T, js string) *RouteRule {
	t.Helper()
	rr, err := ParseRouteRule([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func toStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}
