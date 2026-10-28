// Package profile turns a subscription (Clash YAML or a list of share links) into the parts of a
// mihomo config: proxies, proxy groups, rules and providers. Nodes this core cannot run are kept
// in Profile.Unsupported with a reason, never silently dropped, so the app can grey them out.
package profile

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/convert"
	"go.yaml.in/yaml/v3"
)

// Kind is the format a subscription was written in.
type Kind int

const (
	KindUnknown Kind = iota
	KindClashYAML
	KindURIList
	// KindSingBoxJSON is the main core's own JSON (outbounds); mapped to mihomo proxies by
	// package singbox (block M2), not here.
	KindSingBoxJSON
)

func (k Kind) String() string {
	switch k {
	case KindClashYAML:
		return "clash-yaml"
	case KindURIList:
		return "uri-list"
	case KindSingBoxJSON:
		return "singbox-json"
	}
	return "unknown"
}

// Reasons a node is unavailable on this core (machine-readable; the app shows its own text).
const (
	ReasonUnsupportedProtocol = "unsupported_protocol" // the protocol has no mihomo implementation
	ReasonNotBuilt            = "not_built"            // mihomo has it, but this build leaves it out
	ReasonInvalid             = "invalid"              // the link or entry could not be read
)

// Unsupported is a node kept out of the running config, with why.
type Unsupported struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Profile is a parsed subscription.
type Profile struct {
	Kind          Kind
	Proxies       []map[string]any
	Groups        []map[string]any
	Rules         []string
	Providers     map[string]any // proxy-providers
	RuleProviders map[string]any // rule-providers
	SubRules      map[string]any // sub-rules
	Unsupported   []Unsupported
}

// ErrSingBoxJSON is returned for the main core's JSON format; package singbox maps it.
var ErrSingBoxJSON = errors.New("profile: sing-box JSON is mapped by package singbox")

// ErrEmpty is returned when the subscription holds no node at all (supported or not).
var ErrEmpty = errors.New("profile: no nodes found")

// Built-in policies a group or rule may name without a matching proxy.
var builtinPolicies = map[string]bool{
	"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true,
}

// proxy types mihomo v1.19.33 implements (adapter/parser.go) and this build includes
var supportedTypes = map[string]bool{
	"ss": true, "ssr": true, "socks5": true, "http": true, "vmess": true, "vless": true, "snell": true,
	"trojan": true, "hysteria": true, "hysteria2": true, "wireguard": true, "tuic": true,
	"shadowquic": true, "gost-relay": true, "direct": true, "dns": true, "reject": true,
	"rematch": true, "ssh": true, "mieru": true, "anytls": true, "sudoku": true, "masque": true,
	"trusttunnel": true, "openvpn": true,
}

// left out by the build tags (no_tailscale, no_zerotier, no_easytier); see BuildTags
var trimmedTypes = map[string]bool{"tailscale": true, "zerotier": true, "easytier": true}

// BuildTags are the tags every build of this module uses (CI and the size report).
const BuildTags = "with_gvisor,no_tailscale,no_zerotier,no_easytier"

// SupportedType reports whether proxies of type t can run on this build.
func SupportedType(t string) bool { return supportedTypes[strings.ToLower(t)] }

// Parse reads a subscription body.
func Parse(content []byte) (*Profile, error) {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf"))
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil, ErrEmpty
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return &Profile{Kind: KindSingBoxJSON}, ErrSingBoxJSON
	}
	if p, ok, err := parseClashYAML(trimmed); ok {
		return p, err
	}
	return parseURIList(trimmed)
}

func parseClashYAML(content []byte) (*Profile, bool, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(content, &raw); err != nil || raw == nil {
		return nil, false, nil
	}
	_, hasProxies := raw["proxies"]
	_, hasProviders := raw["proxy-providers"]
	if !hasProxies && !hasProviders {
		return nil, false, nil
	}
	p := &Profile{Kind: KindClashYAML}
	removed := map[string]bool{}
	if list, ok := raw["proxies"].([]any); ok {
		for i, item := range list {
			m, ok := toStringMap(item)
			if !ok {
				p.Unsupported = append(p.Unsupported, Unsupported{Name: "#" + strconv.Itoa(i+1), Reason: ReasonInvalid, Detail: "not a mapping"})
				continue
			}
			name, _ := m["name"].(string)
			typ, _ := m["type"].(string)
			typ = strings.ToLower(typ)
			switch {
			case name == "":
				p.Unsupported = append(p.Unsupported, Unsupported{Name: "#" + strconv.Itoa(i+1), Type: typ, Reason: ReasonInvalid, Detail: "missing name"})
			case trimmedTypes[typ]:
				p.Unsupported = append(p.Unsupported, Unsupported{Name: name, Type: typ, Reason: ReasonNotBuilt})
				removed[name] = true
			case !supportedTypes[typ]:
				p.Unsupported = append(p.Unsupported, Unsupported{Name: name, Type: typ, Reason: ReasonUnsupportedProtocol})
				removed[name] = true
			default:
				p.Proxies = append(p.Proxies, m)
			}
		}
	}
	if list, ok := raw["proxy-groups"].([]any); ok {
		for _, item := range list {
			if m, ok := toStringMap(item); ok {
				p.Groups = append(p.Groups, m)
			}
		}
	}
	if list, ok := raw["rules"].([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok {
				p.Rules = append(p.Rules, s)
			}
		}
	}
	p.Providers, _ = toStringMap(raw["proxy-providers"])
	p.RuleProviders, _ = toStringMap(raw["rule-providers"])
	p.SubRules, _ = toStringMap(raw["sub-rules"])
	if len(removed) > 0 {
		p.dropReferences(removed)
	}
	if len(p.Proxies) == 0 && len(p.Providers) == 0 && len(p.Unsupported) == 0 {
		return nil, true, ErrEmpty
	}
	return p, true, nil
}

// dropReferences removes unavailable nodes from group member lists and points rules that sent
// traffic to them at REJECT (fail closed: their traffic must not leave unproxied). A group left
// with no member and no provider gets REJECT so the config still loads.
func (p *Profile) dropReferences(removed map[string]bool) {
	for _, g := range p.Groups {
		list, ok := g["proxies"].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(list))
		for _, n := range list {
			if s, ok := n.(string); ok && removed[s] {
				continue
			}
			kept = append(kept, n)
		}
		_, hasUse := g["use"]
		_, hasFilter := g["include-all"]
		if len(kept) == 0 && !hasUse && !hasFilter {
			kept = append(kept, "REJECT")
		}
		g["proxies"] = kept
	}
	for i, r := range p.Rules {
		parts := strings.Split(r, ",")
		// TYPE,PAYLOAD,TARGET[,options] or MATCH,TARGET
		idx := 2
		if len(parts) == 2 {
			idx = 1
		}
		if idx < len(parts) && removed[strings.TrimSpace(parts[idx])] {
			parts[idx] = "REJECT"
			p.Rules[i] = strings.Join(parts, ",")
		}
	}
}

// URI schemes mihomo's converter reads (common/convert/converter.go)
var convertSchemes = map[string]bool{
	"hysteria": true, "hysteria2": true, "hy2": true, "hysteria2+realm": true, "hy2+realm": true,
	"tuic": true, "trojan": true, "vless": true, "vmess": true, "ss": true, "ssr": true,
	"socks": true, "socks5": true, "socks5h": true, "http": true, "https": true, "anytls": true,
	"mierus": true,
}

func parseURIList(content []byte) (*Profile, error) {
	data := convert.DecodeBase64(content)
	p := &Profile{Kind: KindURIList}
	names := map[string]int{}
	for _, raw := range bytes.Split(data, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		scheme, _, found := strings.Cut(line, "://")
		if !found {
			continue // not a link (comment, header text)
		}
		scheme = strings.ToLower(scheme)
		if !convertSchemes[scheme] {
			p.Unsupported = append(p.Unsupported, Unsupported{Name: linkName(line), Type: scheme, Reason: ReasonUnsupportedProtocol})
			continue
		}
		proxies, err := convert.ConvertsV2Ray([]byte(line))
		if err != nil || len(proxies) == 0 {
			detail := "unreadable link"
			if err != nil {
				detail = err.Error()
			}
			p.Unsupported = append(p.Unsupported, Unsupported{Name: linkName(line), Type: scheme, Reason: ReasonInvalid, Detail: detail})
			continue
		}
		for _, px := range proxies {
			name, _ := px["name"].(string)
			px["name"] = uniqueName(names, name)
			p.Proxies = append(p.Proxies, px)
		}
	}
	if len(p.Proxies) == 0 && len(p.Unsupported) == 0 {
		return nil, ErrEmpty
	}
	return p, nil
}

func uniqueName(names map[string]int, name string) string {
	if name == "" {
		name = "node"
	}
	n, dup := names[name]
	if !dup {
		names[name] = 0
		return name
	}
	for {
		n++
		candidate := fmt.Sprintf("%s-%02d", name, n)
		if _, taken := names[candidate]; !taken {
			names[name] = n
			names[candidate] = 0
			return candidate
		}
	}
}

// linkName is the #fragment of a share link (its display name), or the link's host.
func linkName(line string) string {
	if i := strings.LastIndexByte(line, '#'); i >= 0 && i+1 < len(line) {
		if s, err := unescape(line[i+1:]); err == nil && s != "" {
			return s
		}
		return line[i+1:]
	}
	rest := line
	if _, after, ok := strings.Cut(line, "://"); ok {
		rest = after
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func toStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out, true
	}
	return nil, false
}

func unescape(s string) (string, error) { return url.PathUnescape(s) }

// Reject moves Proxies[idx] to Unsupported (the core refused it) and drops references to it.
// It reports false when idx is out of range.
func (p *Profile) Reject(idx int, detail string) bool {
	if idx < 0 || idx >= len(p.Proxies) {
		return false
	}
	px := p.Proxies[idx]
	name, _ := px["name"].(string)
	typ, _ := px["type"].(string)
	p.Proxies = append(p.Proxies[:idx:idx], p.Proxies[idx+1:]...)
	p.Unsupported = append(p.Unsupported, Unsupported{Name: name, Type: typ, Reason: ReasonInvalid, Detail: detail})
	if name != "" {
		p.dropReferences(map[string]bool{name: true})
	}
	return true
}
