package options

// Block M3-4: the app's routing rules ("route-rule", the same list the main core gets) and its
// region, as mihomo rules, rule providers and DNS policy, so 兼容内核 splits traffic the way the
// main core does: in 规则 mode mainland sites and IPs (geosite-cn / geoip-cn) go direct and
// mainland domains are resolved by the direct (mainland) DNS; everything else follows the
// subscription's own rules and in the end the main group. In 全局 mode the app has already left
// the direct rules out of the list (except 局域网), so the same mapping gives 全局 here too.
//
// Rule sets: mihomo does not read the main core's .srs files. A geosite-<name> / geoip-<name>
// rule set becomes the same list in mihomo's binary format (.mrs) from the public geo data the
// project already uses; it is downloaded through the main group into the core's own directory
// and re-checked every 5 days (the main core's interval), so nothing extra wakes the device.
// A rule set it cannot map is left out with a warning, like the main core drops a rule set it
// cannot load; a rule left without any condition is dropped (it would match everything).

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// RouteRule is the app's rule list (proto3 JSON of config.RouteRule; unknown fields ignored).
type RouteRule struct {
	Rules []AppRule `json:"rules"`
}

// AppRule is one rule of the list. Enum fields arrive as their names ("direct") or numbers.
type AppRule struct {
	ListOrder        int64             `json:"list_order"`
	Enabled          bool              `json:"enabled"`
	Name             string            `json:"name"`
	Outbound         json.RawMessage   `json:"outbound"`
	RuleSets         []string          `json:"rule_set"`
	PackageNames     []string          `json:"package_name"`
	ProcessNames     []string          `json:"process_name"`
	ProcessPaths     []string          `json:"process_path"`
	Network          json.RawMessage   `json:"network"`
	PortRanges       []string          `json:"port_range"`
	SourcePortRanges []string          `json:"source_port_range"`
	Protocols        []json.RawMessage `json:"protocol"`
	IPCIDRs          []string          `json:"ip_cidr"`
	SourceIPCIDRs    []string          `json:"source_ip_cidr"`
	Domains          []string          `json:"domain"`
	DomainSuffixes   []string          `json:"domain_suffix"`
	DomainKeywords   []string          `json:"domain_keyword"`
	DomainRegexes    []string          `json:"domain_regex"`
}

// Outbound of an app rule: proxy (0, the default), direct (1), direct_with_fragment (2), block (3).
func (r AppRule) target() string {
	switch enumName(r.Outbound, []string{"proxy", "direct", "direct_with_fragment", "block"}) {
	case "direct", "direct_with_fragment":
		return "DIRECT"
	case "block":
		return "REJECT"
	}
	return GroupSelect
}

func (r AppRule) network() string {
	switch enumName(r.Network, []string{"all", "tcp", "udp"}) {
	case "tcp":
		return "TCP"
	case "udp":
		return "UDP"
	}
	return ""
}

func enumName(raw json.RawMessage, names []string) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return names[0]
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n >= 0 && n < len(names) {
			return names[n]
		}
		return ""
	}
	return strings.ToLower(strings.Trim(s, `"`))
}

// GeoDataBase is where the .mrs lists come from (public, free; the same data mihomo users rely on).
const GeoDataBase = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/"

// RuleSetInterval is how often a downloaded list is re-checked while connected (the main core: 5 days).
const RuleSetInterval = 5 * 24 * 3600

// RuleProvider is a rule set mapped from the app's rule-set link.
type RuleProvider struct {
	Name     string // provider name, "muse-geosite-cn"
	Behavior string // domain | ipcidr
	URL      string
}

// MapRuleSet maps a main-core rule-set link (…/geosite-<name>.srs, …/geoip-<name>.srs; "{region}"
// replaced by the region) to a mihomo rule provider. ok is false for a link it cannot map, or
// one that still needs a region while the region is unset / "other".
func MapRuleSet(url, region string) (RuleProvider, bool) {
	u := strings.SplitN(strings.SplitN(url, "?", 2)[0], "#", 2)[0]
	base := path.Base(u)
	if strings.Contains(base, "{region}") {
		region = strings.ToLower(strings.TrimSpace(region))
		if region == "" || region == "other" {
			return RuleProvider{}, false
		}
		base = strings.ReplaceAll(base, "{region}", region)
	}
	if !strings.HasSuffix(base, ".srs") && !strings.HasSuffix(base, ".json") {
		return RuleProvider{}, false
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(base, ".srs"), ".json")
	var kind, name string
	switch {
	case strings.HasPrefix(stem, "geosite-"):
		kind, name = "geosite", strings.TrimPrefix(stem, "geosite-")
	case strings.HasPrefix(stem, "geoip-"):
		kind, name = "geoip", strings.TrimPrefix(stem, "geoip-")
	default:
		return RuleProvider{}, false
	}
	if name == "" || strings.ContainsAny(name, "/\\ ,()") {
		return RuleProvider{}, false
	}
	rp := RuleProvider{Name: "muse-" + kind + "-" + name, URL: GeoDataBase + kind + "/" + name + ".mrs", Behavior: "domain"}
	if kind == "geoip" {
		rp.Behavior = "ipcidr"
	}
	return rp, true
}

// RoutePlan is what the app's rules become in the mihomo config.
type RoutePlan struct {
	Rules     []string                // in order, before the subscription's own rules
	Providers map[string]RuleProvider // by name
	DirectDNS []string                // nameserver-policy keys resolved by the direct DNS
	Process   bool                    // a rule matches apps: process lookup must be on
	Skipped   []string                // why a rule (or part of one) was left out
}

// PlanRoutes maps the enabled rules in their list order.
func PlanRoutes(rr *RouteRule, region string) RoutePlan {
	plan := RoutePlan{Providers: map[string]RuleProvider{}}
	if rr == nil {
		return plan
	}
	rules := make([]AppRule, 0, len(rr.Rules))
	for _, r := range rr.Rules {
		if r.Enabled {
			rules = append(rules, r)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ListOrder < rules[j].ListOrder })
	seenDNS := map[string]bool{}
	for _, r := range rules {
		plan.add(r, region, seenDNS)
	}
	return plan
}

func (plan *RoutePlan) skip(r AppRule, why string) {
	name := r.Name
	if name == "" {
		name = "(unnamed)"
	}
	plan.Skipped = append(plan.Skipped, name+": "+why)
}

// a payload that would break mihomo's comma / parenthesis rule syntax
func badPayload(s string) bool { return s == "" || strings.ContainsAny(s, ",()\n") }

func (plan *RoutePlan) add(r AppRule, region string, seenDNS map[string]bool) {
	target := r.target()
	// destination conditions: any one of them matches (like the main core)
	var dest []string
	var dnsKeys []string
	for _, d := range r.Domains {
		if d = strings.TrimSpace(d); !badPayload(d) {
			dest = append(dest, "DOMAIN,"+d)
			dnsKeys = append(dnsKeys, d)
		}
	}
	for _, d := range r.DomainSuffixes {
		d = strings.TrimPrefix(strings.TrimSpace(d), ".")
		if !badPayload(d) {
			dest = append(dest, "DOMAIN-SUFFIX,"+d)
			dnsKeys = append(dnsKeys, "+."+d)
		}
	}
	for _, d := range r.DomainKeywords {
		if d = strings.TrimSpace(d); !badPayload(d) {
			dest = append(dest, "DOMAIN-KEYWORD,"+d)
		}
	}
	for _, d := range r.DomainRegexes {
		// parentheses are fine in a plain rule (only a combined rule cannot hold them, see below)
		if d = strings.TrimSpace(d); d == "" || strings.ContainsAny(d, ",\n") {
			plan.skip(r, "regex "+strconv.Quote(d)+" cannot be written as a rule")
		} else {
			dest = append(dest, "DOMAIN-REGEX,"+d)
		}
	}
	for _, c := range r.IPCIDRs {
		if c = strings.TrimSpace(c); !badPayload(c) {
			kw := "IP-CIDR"
			if strings.Contains(c, ":") {
				kw = "IP-CIDR6"
			}
			dest = append(dest, kw+","+c+",no-resolve")
		}
	}
	mapped := 0
	for _, u := range r.RuleSets {
		rp, ok := MapRuleSet(u, region)
		if !ok {
			if !strings.Contains(u, "{region}") {
				plan.skip(r, "rule set "+u+" has no mihomo list")
			}
			continue
		}
		mapped++
		plan.Providers[rp.Name] = rp
		if rp.Behavior == "ipcidr" {
			dest = append(dest, "RULE-SET,"+rp.Name)
		} else {
			dest = append(dest, "RULE-SET,"+rp.Name)
			dnsKeys = append(dnsKeys, "rule-set:"+rp.Name)
		}
	}
	// a rule whose only destination was an unmapped rule set would otherwise match everything
	if len(r.RuleSets) > 0 && mapped == 0 && len(dest) == 0 {
		return
	}

	// qualifiers: all of them must match
	var quals []string
	if n := r.network(); n != "" {
		quals = append(quals, "NETWORK,"+n)
	}
	if p := portPayload(r.PortRanges); p != "" {
		quals = append(quals, "DST-PORT,"+p)
	}
	if p := portPayload(r.SourcePortRanges); p != "" {
		quals = append(quals, "SRC-PORT,"+p)
	}
	if len(r.SourceIPCIDRs) > 0 {
		var src []string
		for _, c := range r.SourceIPCIDRs {
			if c = strings.TrimSpace(c); !badPayload(c) {
				src = append(src, "SRC-IP-CIDR,"+c)
			}
		}
		if q := anyOf(src); q != "" {
			quals = append(quals, q)
		}
	}
	var apps []string
	for _, p := range append(append([]string(nil), r.ProcessNames...), r.PackageNames...) {
		if p = strings.TrimSpace(p); !badPayload(p) {
			apps = append(apps, "PROCESS-NAME,"+p)
		}
	}
	for _, p := range r.ProcessPaths {
		if p = strings.TrimSpace(p); !badPayload(p) {
			apps = append(apps, "PROCESS-PATH,"+p)
		}
	}
	if len(apps) > 0 {
		plan.Process = true
		quals = append(quals, anyOf(apps))
	}
	for _, raw := range r.Protocols {
		switch enumName(raw, []string{"tls", "http", "quic", "stun", "dns", "bittorrent"}) {
		case "quic":
			quals = append(quals, "AND,((NETWORK,UDP),(DST-PORT,443))")
		case "dns":
			quals = append(quals, "DST-PORT,53")
		default:
			// mihomo matches no sniffed protocol: the rule would be broader than the user's
			plan.skip(r, "protocol condition not available on this core")
			return
		}
	}
	if len(dest) == 0 && len(quals) == 0 {
		return
	}
	if len(dest) == 0 {
		plan.Rules = append(plan.Rules, allOf(quals)+","+target)
	} else {
		for _, d := range dest {
			if len(quals) == 0 {
				if strings.HasSuffix(d, ",no-resolve") {
					plan.Rules = append(plan.Rules, strings.TrimSuffix(d, ",no-resolve")+","+target+",no-resolve")
				} else {
					plan.Rules = append(plan.Rules, d+","+target)
				}
				continue
			}
			if strings.ContainsAny(d, "()") {
				plan.skip(r, strconv.Quote(d)+" cannot be combined with the rule's other conditions")
				continue
			}
			plan.Rules = append(plan.Rules, allOf(append([]string{strings.TrimSuffix(d, ",no-resolve")}, quals...))+","+target)
		}
	}
	// mainland / direct domains are resolved by the direct DNS (main core: a DNS rule per direct rule);
	// a rule limited to some apps or ports says nothing about the domain itself
	if target == "DIRECT" && len(quals) == 0 {
		for _, k := range dnsKeys {
			if !seenDNS[k] {
				seenDNS[k] = true
				plan.DirectDNS = append(plan.DirectDNS, k)
			}
		}
	}
}

// "(A),(B)" sub-rules joined: AND / OR need at least two, a single one stands alone.
func allOf(parts []string) string { return logic("AND", parts) }
func anyOf(parts []string) string { return logic("OR", parts) }

func logic(op string, parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	wrapped := make([]string, len(parts))
	for i, p := range parts {
		wrapped[i] = "(" + p + ")"
	}
	return op + ",(" + strings.Join(wrapped, ",") + ")"
}

// portPayload: "443", "1000:2000" (main core) → mihomo "443/1000-2000" (at most 28 ranges).
func portPayload(ranges []string) string {
	var out []string
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		r = strings.ReplaceAll(r, ":", "-")
		if strings.HasPrefix(r, "-") {
			r = "0" + r
		}
		if strings.HasSuffix(r, "-") {
			r += "65535"
		}
		ok := true
		for _, part := range strings.SplitN(r, "-", 2) {
			if n, err := strconv.Atoi(part); err != nil || n < 0 || n > 65535 {
				ok = false
			}
		}
		if ok {
			out = append(out, r)
		}
		if len(out) == 28 {
			break
		}
	}
	return strings.Join(out, "/")
}

// ParseRouteRule reads the settings' "route-rule" (absent / null → nil).
func ParseRouteRule(raw json.RawMessage) (*RouteRule, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil, nil
	}
	var rr RouteRule
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, fmt.Errorf("route-rule: %w", err)
	}
	return &rr, nil
}
