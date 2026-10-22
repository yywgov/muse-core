package config

// 穿云 1.4.0: options the app sends beside its rule list —
//   - muse-hosts: custom hosts (domain -> IP), answered by the static DNS server;
//   - muse-node-rules: sites / apps / processes sent through one chosen node (outbound tag),
//     placed before the app's other rules; a rule naming a node that is not in the config is
//     dropped instead of failing the start.

import (
	"net/netip"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type MuseNodeRule struct {
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	ProcessName  []string `json:"process_name,omitempty"`
	PackageName  []string `json:"package_name,omitempty"`
	Outbound     string   `json:"outbound"`
}

// museAddHosts puts valid hosts entries into the static DNS table; returns the domains added.
func museAddHosts(hosts map[string]string, static map[string][]string) []string {
	domains := []string{}
	for d, ip := range hosts {
		d = strings.ToLower(strings.TrimSpace(d))
		ip = strings.TrimSpace(ip)
		if d == "" || !strings.Contains(d, ".") {
			continue
		}
		if _, err := netip.ParseAddr(ip); err != nil {
			continue
		}
		static[d] = []string{ip}
		domains = append(domains, d)
	}
	return domains
}

// museHostsDNSRule sends the hosts domains to the static DNS server.
func museHostsDNSRule(domains []string) option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: badoption.Listable[string](domains)},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{Server: DNSStaticTag},
			},
		},
	}
}

func museOutboundTags(options *option.Options) map[string]bool {
	tags := map[string]bool{}
	for _, o := range options.Outbounds {
		tags[o.Tag] = true
	}
	for _, e := range options.Endpoints {
		tags[e.Tag] = true
	}
	return tags
}

// museNodeRouteRules turns the node rules into route rules (only for nodes that exist and rules
// that match something).
func museNodeRouteRules(rules []MuseNodeRule, tags map[string]bool) []option.Rule {
	out := []option.Rule{}
	for _, r := range rules {
		if r.Outbound == "" || !tags[r.Outbound] {
			continue
		}
		if len(r.DomainSuffix)+len(r.Domain)+len(r.ProcessName)+len(r.PackageName) == 0 {
			continue
		}
		out = append(out, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain:       badoption.Listable[string](r.Domain),
					DomainSuffix: badoption.Listable[string](r.DomainSuffix),
					ProcessName:  badoption.Listable[string](r.ProcessName),
					PackageName:  badoption.Listable[string](r.PackageName),
				},
				RuleAction: option.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{Outbound: r.Outbound},
				},
			},
		})
	}
	return out
}

// museApplyExtras adds the hosts DNS rule and the node rules to a built config. The node rules
// go right after the sniff / DNS-hijack rules at the top, so they win over every other rule.
func museApplyExtras(options *option.Options, hopt *HiddifyOptions, hostDomains []string) {
	if len(hostDomains) > 0 && options.DNS != nil {
		options.DNS.Rules = append([]option.DNSRule{museHostsDNSRule(hostDomains)}, options.DNS.Rules...)
	}
	if len(hopt.MuseNodeRules) == 0 || options.Route == nil {
		return
	}
	nodeRules := museNodeRouteRules(hopt.MuseNodeRules, museOutboundTags(options))
	if len(nodeRules) == 0 {
		return
	}
	at := 0
	for at < len(options.Route.Rules) {
		a := options.Route.Rules[at].DefaultOptions.RuleAction.Action
		if a != C.RuleActionTypeSniff && a != C.RuleActionTypeHijackDNS {
			break
		}
		at++
	}
	rules := append([]option.Rule{}, options.Route.Rules[:at]...)
	rules = append(rules, nodeRules...)
	options.Route.Rules = append(rules, options.Route.Rules[at:]...)
}
