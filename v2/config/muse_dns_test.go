package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// the app's default list in 规则 mode (局域网 / 去广告 / 国内直连), as SingboxConfigOption.toJson sends it
const museDefaultRouteRule = `"route-rule":{"rules":[
	{"list_order":0,"enabled":true,"name":"builtin:bypassLan","outbound":"direct","ip_cidr":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","fc00::/7"]},
	{"list_order":1,"enabled":true,"name":"builtin:blockAds","outbound":"block","rule_set":["` + geoURL + `/block/geosite-category-ads-all.srs","` + geoURL + `/block/geoip-malware.srs"]},
	{"list_order":2,"enabled":true,"name":"builtin:bypassRegion","outbound":"direct","rule_set":["` + geoURL + `/country/geosite-{region}.srs","` + geoURL + `/country/geoip-{region}.srs"]}
]}`

// what the app sends on every platform (direct DNS fixed to 223.5.5.5, remote tcp://8.8.8.8)
func museAppSettings(extra string) string {
	return `{"region":"cn","chain-status":"off","direct-dns-address":"udp://223.5.5.5","remote-dns-address":"tcp://8.8.8.8",` +
		`"ipv6-mode":"ipv4_only","enable-tun":true,` + extra + museDefaultRouteRule + `}`
}

func TestMuseDirectDNSGroupAddresses(t *testing.T) {
	cases := map[string][]string{
		"udp://223.5.5.5": {"udp://223.5.5.5", "tcp://223.5.5.5", "udp://119.29.29.29", "tcp://119.29.29.29"},
		"223.5.5.5":       {"udp://223.5.5.5", "tcp://223.5.5.5", "udp://119.29.29.29", "tcp://119.29.29.29"},
		// DNSPod already selected: fall back to AliDNS
		"udp://119.29.29.29":               {"udp://119.29.29.29", "tcp://119.29.29.29", "udp://223.5.5.5", "tcp://223.5.5.5"},
		"https://dns.alidns.com/dns-query": {"https://dns.alidns.com/dns-query", "udp://119.29.29.29", "tcp://119.29.29.29"},
		"tcp://119.29.29.29":               {"tcp://119.29.29.29", "udp://223.5.5.5", "tcp://223.5.5.5"},
		"local":                            {"local", "udp://119.29.29.29", "tcp://119.29.29.29"},
	}
	for selected, want := range cases {
		got := museDirectDNSGroupAddresses(selected)
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", selected, got, want)
		}
		for _, address := range got[1:] {
			// the fallbacks are domestic, never a resolver abroad or TLS (blocked / slow from mainland China)
			if strings.Contains(address, "8.8.8.8") || strings.Contains(address, "1.1.1.1") || strings.HasPrefix(address, "tls://") {
				t.Errorf("%s: fallback %s is not a quick domestic resolver", selected, address)
			}
		}
	}
}

func TestMuseRemoteDNSGroupAddresses(t *testing.T) {
	cases := map[string][]string{
		"tcp://8.8.8.8":                {"tcp://8.8.8.8", "tcp://1.1.1.1"},
		"https://1.1.1.1/dns-query":    {"https://1.1.1.1/dns-query", "tcp://8.8.8.8"},
		"udp://9.9.9.9":                {"udp://9.9.9.9", "tcp://8.8.8.8"},
		"https://8.8.8.8/dns-query":    {"https://8.8.8.8/dns-query", "tcp://1.1.1.1"},
		"quic://94.140.14.140":         {"quic://94.140.14.140", "tcp://8.8.8.8"},
		"https://dns.google/dns-query": {"https://dns.google/dns-query", "tcp://8.8.8.8"},
	}
	for selected, want := range cases {
		if got := museRemoteDNSGroupAddresses(selected); !slices.Equal(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", selected, got, want)
		}
	}
}

func museServers(options *option.Options) map[string]option.DNSServerOptions {
	servers := map[string]option.DNSServerOptions{}
	for _, server := range options.DNS.Servers {
		servers[server.Tag] = server
	}
	return servers
}

// museDirectGroupMembers: the direct group's members with their address and detour
func museDirectGroupMembers(t *testing.T, options *option.Options) []option.DNSServerOptions {
	t.Helper()
	servers := museServers(options)
	group, ok := servers[DNSMultiDirectTag]
	if !ok || group.Type != C.DNSTypeGroup {
		t.Fatalf("direct DNS group missing")
	}
	var members []option.DNSServerOptions
	for _, tag := range group.Options.(*option.GroupDNSServerOptions).Servers {
		members = append(members, servers[tag])
	}
	return members
}

func TestMuseDomesticDNSIsDirectAndDomestic(t *testing.T) {
	options := buildChainConfig(t, museAppSettings(""))

	members := museDirectGroupMembers(t, options)
	if len(members) != 4 {
		t.Fatalf("direct group has %d members, want 4", len(members))
	}
	wantTypes := []string{C.DNSTypeUDP, C.DNSTypeTCP, C.DNSTypeUDP, C.DNSTypeTCP}
	wantServers := []string{"223.5.5.5", "223.5.5.5", "119.29.29.29", "119.29.29.29"}
	for i, member := range members {
		remote := member.Options.(*option.RemoteDNSServerOptions)
		if member.Type != wantTypes[i] || remote.Server != wantServers[i] {
			t.Fatalf("direct member %d = %s %s, want %s %s", i, member.Type, remote.Server, wantTypes[i], wantServers[i])
		}
		// dialled directly, never through the node
		if remote.Detour != "" {
			t.Fatalf("direct member %d detour %q, want direct", i, remote.Detour)
		}
	}

	// 国内域名 (geosite-cn) and names whose direct answer is in geoip-cn use the direct group,
	// with the server's own TTL; everything else ends at the remote group
	var siteRule, ipRule *option.DefaultDNSRule
	for i := range options.DNS.Rules {
		rule := &options.DNS.Rules[i].DefaultOptions
		switch strings.Join(rule.RuleSet, ",") {
		case "geosite-cn":
			siteRule = rule
		case "geoip-cn":
			ipRule = rule
		}
	}
	for name, rule := range map[string]*option.DefaultDNSRule{"geosite-cn": siteRule, "geoip-cn": ipRule} {
		if rule == nil {
			t.Fatalf("no DNS rule for %s", name)
		}
		if rule.RouteOptions.Server != DNSMultiDirectTag {
			t.Fatalf("%s DNS rule server %q, want the direct group", name, rule.RouteOptions.Server)
		}
		if rule.RouteOptions.RewriteTTL != nil {
			t.Fatalf("%s answers get TTL %d, want the server's own", name, *rule.RouteOptions.RewriteTTL)
		}
	}
	if options.DNS.Final != DNSMultiRemoteTag {
		t.Fatalf("DNS final %q", options.DNS.Final)
	}

	// the cache expires with the real TTL; an expired answer is served once while refreshed
	client := options.DNS.DNSClientOptions
	if client.DisableExpire {
		t.Fatal("DNS cache must expire")
	}
	if client.Optimistic == nil || !client.Optimistic.Enabled {
		t.Fatal("optimistic DNS cache is off")
	}
	if client.CacheCapacity != museDNSCacheCapacity {
		t.Fatalf("cache capacity %d", client.CacheCapacity)
	}

	// remote group: selected server plus one TCP fallback, both through the node
	servers := museServers(options)
	remote := servers[DNSMultiRemoteTag].Options.(*option.GroupDNSServerOptions).Servers
	if len(remote) != 2 || remote[0] != DNSRemoteTag {
		t.Fatalf("remote group %v", remote)
	}
	fallback := servers[remote[1]]
	if fallback.Type != C.DNSTypeTCP || fallback.Options.(*option.RemoteDNSServerOptions).Detour != OutboundSelectTag {
		t.Fatalf("remote fallback %s detour %q", fallback.Type, fallback.Options.(*option.RemoteDNSServerOptions).Detour)
	}
}

// museRoute walks the route rules for one connection the way sing-box does for these rule kinds:
// sniff / hijack-dns are skipped, resolve fills the addresses of a name, and the first matching
// route / reject rule wins (else route.final). geositeCN / geoipCN stand in for the rule-sets.
func museRoute(options *option.Options, domain string, ip netip.Addr, answer netip.Addr, geositeCN map[string]bool, geoipCN func(netip.Addr) bool) string {
	var addresses []netip.Addr
	if ip.IsValid() {
		addresses = []netip.Addr{ip}
	}
	for _, rule := range options.Route.Rules {
		d := rule.DefaultOptions
		switch d.Action {
		case C.RuleActionTypeSniff, C.RuleActionTypeHijackDNS:
			continue
		case C.RuleActionTypeResolve:
			if !ip.IsValid() && domain != "" {
				addresses = []netip.Addr{answer}
			}
			continue
		}
		raw := d.RawDefaultRule
		if len(raw.Network) > 0 || len(raw.Protocol) > 0 || len(raw.Port) > 0 || len(raw.PortRange) > 0 {
			continue
		}
		matched := false
		for _, cidr := range raw.IPCIDR {
			prefix := netip.MustParsePrefix(cidr)
			for _, a := range addresses {
				matched = matched || prefix.Contains(a)
			}
		}
		for _, tag := range raw.RuleSet {
			switch {
			case strings.HasPrefix(tag, "geosite-cn"):
				matched = matched || geositeCN[domain]
			case strings.HasPrefix(tag, "geoip-cn"):
				for _, a := range addresses {
					matched = matched || geoipCN(a)
				}
			}
		}
		if !matched {
			continue
		}
		if d.Action == C.RuleActionTypeReject {
			return "reject"
		}
		return d.RouteOptions.Outbound
	}
	return options.Route.Final
}

func TestMuseDomesticTrafficGoesDirect(t *testing.T) {
	cnNet := netip.MustParsePrefix("110.242.0.0/16")
	geoipCN := func(a netip.Addr) bool { return cnNet.Contains(a) }
	geositeCN := map[string]bool{"www.taobao.com": true}
	cnIP := netip.MustParseAddr("110.242.68.66")
	abroad := netip.MustParseAddr("142.250.4.100")

	for _, mode := range []struct{ name, extra string }{
		{"tun", ``},
		{"system proxy", `"enable-tun":false,"set-system-proxy":true,`},
	} {
		t.Run(mode.name, func(t *testing.T) {
			options := buildChainConfig(t, museAppSettings(mode.extra))
			cases := []struct {
				what       string
				domain     string
				ip, answer netip.Addr
				want       string
			}{
				// TUN: the app looked the name up itself, the destination is an IP
				{"listed domestic site by IP", "www.taobao.com", cnIP, netip.Addr{}, OutboundDirectTag},
				{"unlisted domestic site by IP", "shop.example.cn", cnIP, netip.Addr{}, OutboundDirectTag},
				{"domestic IP without a name", "", cnIP, netip.Addr{}, OutboundDirectTag},
				{"LAN", "", netip.MustParseAddr("192.168.1.1"), netip.Addr{}, OutboundDirectTag},
				{"foreign site by IP", "www.google.com", abroad, netip.Addr{}, OutboundSelectTag},
				// local proxy port: the destination is a name
				{"listed domestic site by name", "www.taobao.com", netip.Addr{}, cnIP, OutboundDirectTag},
				{"unlisted domestic site by name", "shop.example.cn", netip.Addr{}, cnIP, OutboundDirectTag},
				{"foreign site by name", "www.google.com", netip.Addr{}, abroad, OutboundSelectTag},
			}
			for _, c := range cases {
				if got := museRoute(options, c.domain, c.ip, c.answer, geositeCN, geoipCN); got != c.want {
					t.Errorf("%s: routed to %q, want %q", c.what, got, c.want)
				}
			}
		})
	}
}

func TestMuseResolveRulePlacement(t *testing.T) {
	options := buildChainConfig(t, museAppSettings(""))
	resolveAt, regionAt, lanAt := -1, -1, -1
	for i, rule := range options.Route.Rules {
		d := rule.DefaultOptions
		if d.Action == C.RuleActionTypeResolve {
			if resolveAt >= 0 {
				t.Fatal("more than one resolve rule")
			}
			resolveAt = i
			if d.ResolveOptions.Server != "" {
				t.Fatalf("resolve uses server %q, want the DNS rules", d.ResolveOptions.Server)
			}
		}
		if strings.Join(d.RuleSet, ",") == "geosite-cn,geoip-cn" {
			regionAt = i
		}
		if len(d.IPCIDR) > 0 && d.IPCIDR[0] == "10.0.0.0/8" {
			lanAt = i
		}
	}
	// right before the 国内直连 rule: names the earlier rules decide are not looked up
	if resolveAt < 0 || regionAt != resolveAt+1 || lanAt > resolveAt {
		t.Fatalf("resolve at %d, region rule at %d, LAN at %d", resolveAt, regionAt, lanAt)
	}

	// Fake-IP: names are not looked up
	fake := buildChainConfig(t, museAppSettings(`"enable-fake-dns":true,`))
	for _, rule := range fake.Route.Rules {
		if rule.DefaultOptions.Action == C.RuleActionTypeResolve {
			t.Fatal("resolve rule with fake DNS")
		}
	}
	// 全局 mode (no direct geoip rule): nothing to resolve for
	global := buildChainConfig(t, `{"region":"cn","chain-status":"off","route-rule":{"rules":[
		{"list_order":0,"enabled":true,"name":"builtin:bypassLan","outbound":"direct","ip_cidr":["10.0.0.0/8"]}]}}`)
	for _, rule := range global.Route.Rules {
		if rule.DefaultOptions.Action == C.RuleActionTypeResolve {
			t.Fatal("resolve rule without a direct geoip rule")
		}
	}
}

// QUIC of domestic sites keeps working: the proxied-QUIC reject comes after the 国内直连 rule
func TestMuseDomesticQUICNotRejected(t *testing.T) {
	options := buildChainConfig(t, museAppSettings(""))
	regionAt, quicAt := -1, -1
	for i, rule := range options.Route.Rules {
		d := rule.DefaultOptions
		if strings.Join(d.RuleSet, ",") == "geosite-cn,geoip-cn" {
			regionAt = i
		}
		if d.Action == C.RuleActionTypeReject && slices.Contains(d.Protocol, C.ProtocolQUIC) {
			quicAt = i
		}
	}
	if regionAt < 0 || quicAt < regionAt {
		t.Fatalf("国内直连 at %d, QUIC reject at %d", regionAt, quicAt)
	}
}
