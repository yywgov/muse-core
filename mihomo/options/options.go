// Package options maps the app's settings (the same JSON the main core receives through
// the settings call of the control API) to a mihomo config, around the proxies and groups of a profile.
//
// Block M1 maps the basics (ports, local API, log level, IPv6, LAN access, DNS servers, the
// default groups, test URL/interval). Block M3-4 adds routing like the main core (rules.go: the
// app's rule list and region as rules, rule providers and the direct-DNS policy). Fake-IP and
// finer TUN details are not mapped yet; the defaults below apply.
package options

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yywgov/muse-core/mihomo/profile"
	"go.yaml.in/yaml/v3"
)

// Group names the app expects (same tags as the main core: the main selector and the auto group).
const (
	GroupSelect = "select"
	GroupAuto   = "lowest"
)

// Settings is the subset of the app's settings JSON this core reads; unknown keys are ignored.
type Settings struct {
	LogLevel        string   `json:"log-level"`
	EnableClashAPI  bool     `json:"enable-clash-api"`
	ClashAPIPort    uint16   `json:"clash-api-port"`
	ClashAPISecret  string   `json:"web-secret"`
	MixedPort       uint16   `json:"mixed-port"`
	AllowLAN        bool     `json:"allow-connection-from-lan"`
	IPv6Mode        string   `json:"-"`
	RemoteDNS       string   `json:"remote-dns-address"`
	DirectDNS       string   `json:"direct-dns-address"`
	TestURL         string   `json:"connection-test-url"`
	TestURLs        []string `json:"connection-test-urls"`
	TestIntervalSec int64    `json:"-"`
	EnableTun       bool     `json:"enable-tun"`
	SetSystemProxy  bool     `json:"set-system-proxy"` // Windows 系统代理 mode (package sysproxy)
	TunStack        string   `json:"tun-implementation"`
	MTU             uint32   `json:"mtu"`
	StrictRoute     bool     `json:"strict-route"`
	BypassLAN       bool     `json:"bypass-lan"`
	TestWorkers     int      `json:"muse-test-workers"`    // 4–64, 0 = 16 (same as the main core)
	TestTimeoutMs   int      `json:"muse-test-timeout-ms"` // 0 = 5000
	// M3-4: routing like the main core (rules.go): the region ("cn": mainland direct) and the
	// app's rule list. Kept raw: a list this core cannot read never fails the settings.
	Region       string          `json:"region"`
	RouteRuleRaw json.RawMessage `json:"route-rule"`
}

// Routes maps the app's rule list (rules.go); an unreadable list maps to nothing (logged by the caller).
func (s Settings) Routes() (RoutePlan, error) {
	rr, err := ParseRouteRule(s.RouteRuleRaw)
	if err != nil {
		return PlanRoutes(nil, s.Region), err
	}
	return PlanRoutes(rr, s.Region), nil
}

// Workers is the number of delay tests run at once.
func (s Settings) Workers() int {
	switch {
	case s.TestWorkers <= 0:
		return 16
	case s.TestWorkers < 4:
		return 4
	case s.TestWorkers > 64:
		return 64
	}
	return s.TestWorkers
}

// TestTimeout is the limit of one delay test.
func (s Settings) TestTimeout() time.Duration {
	if s.TestTimeoutMs <= 0 {
		return 5 * time.Second
	}
	return time.Duration(s.TestTimeoutMs) * time.Millisecond
}

// URL is the delay-test URL.
func (s Settings) URL() string {
	if s.TestURL != "" {
		return s.TestURL
	}
	if len(s.TestURLs) > 0 && s.TestURLs[0] != "" {
		return s.TestURLs[0]
	}
	return Defaults().TestURL
}

// SameTun reports whether two settings give the same TUN (a changed TUN cannot be hot reloaded).
func (s Settings) SameTun(o Settings) bool {
	if !s.EnableTun && !o.EnableTun {
		return true
	}
	return s.EnableTun == o.EnableTun && tunStack(s.TunStack) == tunStack(o.TunStack) && s.MTU == o.MTU && s.StrictRoute == o.StrictRoute
}

// Defaults match the main core's defaults for the same keys.
func Defaults() Settings {
	return Settings{
		LogLevel:        "warn",
		EnableClashAPI:  true,
		ClashAPIPort:    16756,
		MixedPort:       12334,
		RemoteDNS:       "1.1.1.1",
		DirectDNS:       "1.1.1.1",
		TestURL:         "http://cp.cloudflare.com/",
		TestIntervalSec: 600,
		TunStack:        "mixed",
		MTU:             9000,
		StrictRoute:     true,
	}
}

// ParseSettings reads the settings JSON over the defaults. An empty string gives the defaults.
func ParseSettings(js string) (Settings, error) {
	s := Defaults()
	if strings.TrimSpace(js) == "" {
		return s, nil
	}
	if err := json.Unmarshal([]byte(js), &s); err != nil {
		return Defaults(), fmt.Errorf("settings: %w", err)
	}
	// fields whose JSON type differs between app versions (string or number)
	var loose map[string]json.RawMessage
	if err := json.Unmarshal([]byte(js), &loose); err == nil {
		if v, ok := loose["ipv6-mode"]; ok {
			s.IPv6Mode = rawString(v)
		}
		if v, ok := loose["url-test-interval"]; ok {
			if n, err := strconv.ParseInt(strings.TrimSuffix(rawString(v), "s"), 10, 64); err == nil && n > 0 {
				s.TestIntervalSec = n
			}
		}
	}
	if s.MixedPort == 0 {
		s.MixedPort = Defaults().MixedPort
	}
	return s, nil
}

func rawString(v json.RawMessage) string {
	var str string
	if json.Unmarshal(v, &str) == nil {
		return str
	}
	return strings.Trim(string(v), `"`)
}

// Runtime is what the service decides at start, not the user.
type Runtime struct {
	// address of mihomo's local REST/WS API; the app's local API client connects here
	ControllerAddr string
	Secret         string
	HomeDir        string
	// Android: the VPN service's TUN file descriptor (the service builds the TUN and routes; the
	// core only reads and writes packets). 0 elsewhere.
	TunFD int
	// Windows: name of the TUN adapter the core creates ("" = engine default)
	TunDevice string
}

// mihomo log levels: debug, info, warning, error, silent
func logLevel(s string) string {
	switch strings.ToLower(s) {
	case "trace", "debug":
		return "debug"
	case "info":
		return "info"
	case "warn", "warning":
		return "warning"
	case "error", "fatal", "panic":
		return "error"
	case "silent", "none", "disabled":
		return "silent"
	}
	return "warning"
}

// ipv6 is false only for an IPv4-only strategy
func ipv6(mode string) bool {
	switch strings.ToLower(mode) {
	case "ipv4_only", "1", "ipv4":
		return false
	}
	return true
}

func tunStack(s string) string {
	switch strings.ToLower(s) {
	case "system":
		return "system"
	case "gvisor":
		return "gvisor"
	}
	return "mixed"
}

func dnsServer(addr string) string {
	addr = strings.TrimSpace(addr)
	switch {
	case addr == "", addr == "local":
		return "system"
	case strings.HasPrefix(addr, "udp://"):
		return strings.TrimPrefix(addr, "udp://")
	}
	return addr
}

// Build renders the full mihomo config for a profile.
func Build(p *profile.Profile, s Settings, rt Runtime) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("options: no profile")
	}
	cfg := map[string]any{
		"mixed-port":                int(s.MixedPort),
		"allow-lan":                 s.AllowLAN,
		"bind-address":              "*",
		"mode":                      "rule",
		"log-level":                 logLevel(s.LogLevel),
		"ipv6":                      ipv6(s.IPv6Mode),
		"unified-delay":             true,
		"tcp-concurrent":            true,
		"find-process-mode":         "off",
		"global-client-fingerprint": "chrome",
		"profile": map[string]any{
			"store-selected": false, // the app restores the selection itself
			"store-fake-ip":  false,
		},
	}
	if !s.AllowLAN {
		cfg["bind-address"] = "127.0.0.1"
	}
	if rt.ControllerAddr != "" {
		cfg["external-controller"] = rt.ControllerAddr
		cfg["secret"] = rt.Secret
	}
	plan, _ := s.Routes()
	if plan.Process {
		// only looked up for the rules that name apps
		cfg["find-process-mode"] = "strict"
	}
	remote, direct := dnsServer(s.RemoteDNS), dnsServer(s.DirectDNS)
	bootstrap := []any{"223.5.5.5", "119.29.29.29"}
	directNS := []any{direct}
	if direct == "system" {
		directNS = []any{"223.5.5.5"}
	}
	// the direct DNS always goes straight out (never through a node), like the main core's
	pinned := make([]any, 0, len(directNS))
	for _, d := range directNS {
		pinned = append(pinned, directOut(fmt.Sprint(d)))
	}
	dns := map[string]any{
		"enable":        true,
		"ipv6":          ipv6(s.IPv6Mode),
		"enhanced-mode": "redir-host",
		// the remote DNS follows the rules (through the node for the rest of the world), like the
		// main core sends it through the main group; node addresses use the direct DNS
		"respect-rules":           true,
		"nameserver":              []any{remote},
		"proxy-server-nameserver": directNS,
		"direct-nameserver":       pinned,
		"default-nameserver":      bootstrap,
	}
	if len(plan.DirectDNS) > 0 {
		policy := map[string]any{}
		for _, k := range plan.DirectDNS {
			policy[k] = pinned
		}
		dns["nameserver-policy"] = policy
	}
	cfg["dns"] = dns
	if s.EnableTun {
		cfg["tun"] = map[string]any{
			"enable":                true,
			"stack":                 tunStack(s.TunStack),
			"mtu":                   int(s.MTU),
			"auto-route":            true,
			"auto-detect-interface": true,
			"strict-route":          s.StrictRoute,
			"dns-hijack":            []any{"any:53"},
		}
		if rt.TunDevice != "" && rt.TunFD == 0 {
			cfg["tun"].(map[string]any)["device"] = rt.TunDevice
		}
		if rt.TunFD > 0 {
			tun := cfg["tun"].(map[string]any)
			tun["file-descriptor"] = rt.TunFD
			// routes, interface and per-app rules belong to the VPN service that made the TUN
			tun["auto-route"] = false
			tun["auto-detect-interface"] = false
			delete(tun, "strict-route")
		}
	}

	proxies := make([]any, 0, len(p.Proxies))
	names := make([]any, 0, len(p.Proxies))
	for _, px := range p.Proxies {
		proxies = append(proxies, px)
		if n, ok := px["name"].(string); ok {
			names = append(names, n)
		}
	}
	cfg["proxies"] = proxies
	if len(p.Providers) > 0 {
		cfg["proxy-providers"] = p.Providers
	}
	ruleProviders := map[string]any{}
	for n, v := range p.RuleProviders {
		ruleProviders[n] = v
	}
	for n, rp := range plan.Providers {
		if _, taken := ruleProviders[n]; taken {
			continue
		}
		ruleProviders[n] = map[string]any{
			"type": "http", "behavior": rp.Behavior, "format": "mrs", "url": rp.URL,
			"path": "./ruleset/" + n + ".mrs", "interval": RuleSetInterval, "proxy": GroupSelect,
		}
	}
	if len(ruleProviders) > 0 {
		cfg["rule-providers"] = ruleProviders
	}
	if len(p.SubRules) > 0 {
		cfg["sub-rules"] = p.SubRules
	}

	testURL := s.URL()
	interval := s.TestIntervalSec
	if interval <= 0 {
		interval = Defaults().TestIntervalSec
	}

	groups := make([]any, 0, len(p.Groups)+2)
	hasGroup := map[string]bool{}
	for _, g := range p.Groups {
		if n, ok := g["name"].(string); ok {
			hasGroup[n] = true
		}
	}
	providerNames := make([]any, 0, len(p.Providers))
	for n := range p.Providers {
		providerNames = append(providerNames, n)
	}
	sortAny(providerNames)
	auto := map[string]any{
		"name": GroupAuto, "type": "url-test", "url": testURL, "interval": int(interval),
		"tolerance": 50, "lazy": true,
	}
	sel := map[string]any{"name": GroupSelect, "type": "select"}
	if len(names) == 0 && len(providerNames) == 0 {
		// every node unavailable: keep the config loadable, fail closed
		auto["proxies"] = []any{"REJECT"}
	} else {
		if len(names) > 0 {
			auto["proxies"] = names
		}
		if len(providerNames) > 0 {
			auto["use"] = providerNames
		}
	}
	selMembers := []any{GroupAuto}
	for _, g := range p.Groups {
		if n, ok := g["name"].(string); ok && n != GroupSelect && n != GroupAuto {
			selMembers = append(selMembers, n)
		}
	}
	selMembers = append(selMembers, names...)
	sel["proxies"] = selMembers
	if len(providerNames) > 0 {
		sel["use"] = providerNames
	}
	if !hasGroup[GroupSelect] {
		groups = append(groups, sel)
	}
	if !hasGroup[GroupAuto] {
		groups = append(groups, auto)
	}
	for _, g := range p.Groups {
		groups = append(groups, g)
	}
	cfg["proxy-groups"] = groups

	rules := make([]any, 0, len(p.Rules)+3)
	if s.BypassLAN {
		rules = append(rules, "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
			"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
	}
	// the app's rules first (国内直连, the user's own, 去广告 …), then the subscription's
	for _, r := range plan.Rules {
		rules = append(rules, r)
	}
	hasMatch := false
	for _, r := range p.Rules {
		rules = append(rules, r)
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(r)), "MATCH,") {
			hasMatch = true
		}
	}
	if !hasMatch {
		rules = append(rules, "MATCH,"+GroupSelect)
	}
	cfg["rules"] = rules
	return yaml.Marshal(cfg)
}

// directOut pins a DNS server to the direct outbound ("223.5.5.5#DIRECT"); "system" stays as is.
func directOut(addr string) string {
	if addr == "system" || strings.Contains(addr, "#") {
		return addr
	}
	return addr + "#DIRECT"
}

func sortAny(v []any) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && fmt.Sprint(v[j]) < fmt.Sprint(v[j-1]); j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
