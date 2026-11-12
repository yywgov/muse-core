package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// 穿云 1.20.4 (core muse.25): the remote DNS group asks its members in parallel (standard sing-box
// group mode), keeping the group's members, ignore range and the direct group's sequential order.
func TestMuseRemoteDNSGroupParallel(t *testing.T) {
	for _, settings := range []string{museAppSettings(""), museAppSettings(`"enable-tun":false,`)} {
		options := buildChainConfig(t, settings)
		servers := museServers(options)
		remote, ok := servers[DNSMultiRemoteTag]
		if !ok || remote.Type != C.DNSTypeGroup {
			t.Fatal("remote DNS group missing")
		}
		g := remote.Options.(*option.GroupDNSServerOptions)
		if g.Mode != C.DNSGroupModeParallel {
			t.Fatalf("remote group mode %q, want %q", g.Mode, C.DNSGroupModeParallel)
		}
		// same two members as before: tcp://8.8.8.8 (selected) + tcp://1.1.1.1, both through the node
		if len(g.Servers) != 2 || g.Servers[0] != DNSRemoteTag {
			t.Fatalf("remote group members %v", g.Servers)
		}
		for _, tag := range g.Servers {
			member := servers[tag].Options.(*option.RemoteDNSServerOptions)
			if member.Detour != OutboundMainDetour {
				t.Fatalf("remote member %s detour %q, want %q", tag, member.Detour, OutboundMainDetour)
			}
		}
		if fallback := servers[g.Servers[1]].Options.(*option.RemoteDNSServerOptions); servers[g.Servers[1]].Type != C.DNSTypeTCP || fallback.Server != "1.1.1.1" {
			t.Fatalf("remote fallback %s %s, want tcp 1.1.1.1", servers[g.Servers[1]].Type, fallback.Server)
		}
		if len(g.IgnoreRanges) != 1 {
			t.Fatalf("remote group ignore ranges %v", g.IgnoreRanges)
		}
		direct := servers[DNSMultiDirectTag].Options.(*option.GroupDNSServerOptions)
		if direct.Mode != C.DNSGroupModeSequential {
			t.Fatalf("direct group mode %q, want sequential (unchanged)", direct.Mode)
		}
	}
}

// 穿云 1.20.4 (core muse.25): answers from the remote group keep the server's TTL (no one-day
// rewrite) and the optimistic cache stays on; the direct side and fake-ip are unchanged.
func TestMuseRemoteDNSKeepsRealTTL(t *testing.T) {
	if museRemoteDNSRewriteTTL != nil {
		t.Fatalf("museRemoteDNSRewriteTTL = %d, want nil (server TTL)", *museRemoteDNSRewriteTTL)
	}
	options := buildChainConfig(t, museAppSettings(""))
	remoteRules := 0
	for _, rule := range options.DNS.Rules {
		r := rule.DefaultOptions
		if r.RouteOptions.Server != DNSMultiRemoteTag {
			continue
		}
		remoteRules++
		if r.RouteOptions.RewriteTTL != nil {
			t.Fatalf("remote DNS rule %+v rewrites TTL to %d", r.RawDefaultDNSRule, *r.RouteOptions.RewriteTTL)
		}
		if r.RouteOptions.DisableCache {
			t.Fatal("remote answers must stay cached")
		}
	}
	if remoteRules == 0 {
		t.Fatal("no DNS rule routes to the remote group")
	}
	client := options.DNS.DNSClientOptions
	if client.DisableExpire || client.Optimistic == nil || !client.Optimistic.Enabled {
		t.Fatalf("cache must expire with the real TTL and stay optimistic: %+v", client)
	}
	// fake-ip (off by default) keeps its own rule unchanged
	fake := buildChainConfig(t, museAppSettings(`"enable-fake-dns":true,`))
	fakeRules := 0
	for _, rule := range fake.DNS.Rules {
		r := rule.DefaultOptions
		if r.RouteOptions.Server != DNSFakeTag {
			continue
		}
		fakeRules++
		if r.RouteOptions.RewriteTTL == nil || *r.RouteOptions.RewriteTTL != DEFAULT_DNS_TTL || !r.RouteOptions.DisableCache {
			t.Fatal("fake-ip rule changed")
		}
	}
	if fakeRules != 1 {
		t.Fatalf("%d fake-ip rules, want 1", fakeRules)
	}
}
