package config

// 穿云 1.6.4 (core muse.18): domestic sites were slow with the app on. Three causes in the DNS this
// package generates (sing-box itself is unchanged):
//
//  1. The DNS groups are sequential and only accept an answer that still has records. An empty
//     but valid answer (AAAA of an IPv4-only site, HTTPS records, NXDOMAIN) moved on to the next
//     member, and the direct group's members after 223.5.5.5 were its TCP/TLS variants and then
//     8.8.8.8 over UDP/TCP/TLS, dialled directly from mainland China, where tls://8.8.8.8 is often
//     dropped: such a lookup waited for the 10 s DNS timeout. A fallback answer from 8.8.8.8 also
//     pointed domestic sites at CDN nodes chosen for Google's resolver, not the user's network.
//     The direct group now only holds domestic resolvers over UDP/TCP (museDirectDNSGroupAddresses),
//     the remote one the selected server plus one TCP fallback through the node.
//  2. The DNS cache never expired (disable_expire) and every direct answer had its TTL rewritten
//     to one day, which apps and the system resolver cached too. CDN answers of domestic sites
//     (TTL 60–600 s, chosen per network) stayed in use after switching Wi‑Fi / mobile data or
//     ISP, often on a slow cross-ISP node. Direct answers now keep their real TTL and the cache
//     expires; an expired entry is served once (TTL 1) while it is refreshed (optimistic), so
//     shorter TTLs cost no waiting. The refresh only happens when an app asks again — no timer.
//  3. A domestic site missing from geosite-cn only went direct through the geoip-cn rule, which
//     needs an IP. In TUN mode the app's own DNS query gives one, but through the local proxy
//     port (系统代理, the Windows default) the destination is a name, the geoip rule never matched
//     and the site went through the node. A resolve rule before the first direct geoip rule
//     (route_rules.go) gives it the same answer TUN mode would have seen.

import (
	"net/url"
	"slices"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	// museDomesticDNS / museDomesticDNSAlt: the direct group's fallback (DNSPod, then AliDNS when
	// DNSPod is already the selected server)
	museDomesticDNS    = "119.29.29.29"
	museDomesticDNSAlt = "223.5.5.5"
	// museDNSCacheCapacity: entries (sing-box's minimum is 1024)
	museDNSCacheCapacity = 4096
	// museDNSOptimisticTimeout: how long after expiry an answer may still be served once while it
	// is refreshed
	museDNSOptimisticTimeout = time.Hour
)

// museDirectDNSRewriteTTL is the TTL direct (domestic) answers are given: nil keeps the server's.
var museDirectDNSRewriteTTL *uint32

func museDNSClientOptions(opt *HiddifyOptions) option.DNSClientOptions {
	return option.DNSClientOptions{
		IndependentCache: opt.IndependentDNSCache && !C.IsIos,
		CacheCapacity:    museDNSCacheCapacity,
		Optimistic: &option.OptimisticDNSOptions{
			Enabled: true,
			Timeout: badoption.Duration(museDNSOptimisticTimeout),
		},
	}
}

// dnsHost returns the normalized address and its bracketed host (empty for local / fakeip / a
// scheme without a host).
func dnsHost(selected string) (string, string, string) {
	if selected != "local" && selected != "fakeip" {
		selected = getDnsAddress(selected)
	}
	host, scheme := "", ""
	if u, err := url.Parse(selected); err == nil {
		switch u.Scheme {
		case C.DNSTypeUDP, C.DNSTypeTCP, C.DNSTypeTLS, C.DNSTypeHTTPS, C.DNSTypeHTTP3, C.DNSTypeQUIC:
			host = u.Hostname()
			scheme = u.Scheme
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return selected, host, scheme
}

func uniqueAddresses(candidates []string) []string {
	var addresses []string
	for _, candidate := range candidates {
		if !slices.Contains(addresses, candidate) {
			addresses = append(addresses, candidate)
		}
	}
	return addresses
}

// museDirectDNSGroupAddresses lists the direct group in order: the selected server, its TCP
// variant when it is plain UDP, then a domestic resolver over UDP and TCP. Every member is a
// quick domestic server, so an empty answer (which makes the group ask the next member) costs a
// few milliseconds per member instead of a timeout abroad.
func museDirectDNSGroupAddresses(selected string) []string {
	selected, host, scheme := dnsHost(selected)
	fallback := museDomesticDNS
	if host == museDomesticDNS {
		fallback = museDomesticDNSAlt
	}
	candidates := []string{selected}
	if scheme == C.DNSTypeUDP && host != "" {
		candidates = append(candidates, "tcp://"+host)
	}
	candidates = append(candidates, "udp://"+fallback, "tcp://"+fallback)
	return uniqueAddresses(candidates)
}

// museRemoteDNSGroupAddresses lists the remote group (dialled through the node): the selected
// server, then one fallback resolver over TCP (UDP may not pass a TCP-only node, and TLS inside
// the node adds a handshake for nothing).
func museRemoteDNSGroupAddresses(selected string) []string {
	selected, host, _ := dnsHost(selected)
	fallback := "8.8.8.8"
	if host == fallback {
		fallback = "1.1.1.1"
	}
	return uniqueAddresses([]string{selected, "tcp://" + fallback})
}

// museResolveRule resolves a destination that is still a name (local proxy port; a no-op for the
// IP destinations of TUN mode) with the DNS rules, so the geoip rules after it can match.
func museResolveRule() option.Rule {
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeResolve,
			},
		},
	}
}
