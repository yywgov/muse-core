package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestMuseHostsAndNodeRules(t *testing.T) {
	static := map[string][]string{}
	domains := museAddHosts(map[string]string{"Example.com ": "1.2.3.4", "bad": "1.1.1.1", "v6.test": "::1", "x.com": "nope"}, static)
	if len(domains) != 2 || static["example.com"][0] != "1.2.3.4" || static["v6.test"][0] != "::1" {
		t.Fatalf("hosts: %v %v", domains, static)
	}
	opts := &option.Options{
		Outbounds: []option.Outbound{{Tag: "JP 01"}, {Tag: "direct"}},
		DNS:       &option.DNSOptions{},
		Route: &option.RouteOptions{Rules: []option.Rule{
			{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeSniff}}},
			{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeHijackDNS}}},
			{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute}}},
		}},
	}
	hopt := &HiddifyOptions{MuseNodeRules: []MuseNodeRule{
		{DomainSuffix: []string{"netflix.com"}, Outbound: "JP 01"},
		{DomainSuffix: []string{"x.com"}, Outbound: "missing"},
		{Outbound: "JP 01"},
	}}
	museApplyExtras(opts, hopt, domains)
	if len(opts.DNS.Rules) != 1 || opts.DNS.Rules[0].DefaultOptions.RouteOptions.Server != DNSStaticTag {
		t.Fatalf("dns rules: %+v", opts.DNS.Rules)
	}
	if len(opts.Route.Rules) != 4 {
		t.Fatalf("route rules: %d", len(opts.Route.Rules))
	}
	r := opts.Route.Rules[2].DefaultOptions
	if r.RouteOptions.Outbound != "JP 01" || r.DomainSuffix[0] != "netflix.com" {
		t.Fatalf("node rule at 2: %+v", r)
	}
}
