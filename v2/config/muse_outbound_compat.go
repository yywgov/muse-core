package config

// 穿云 1.2.9: make share links / Clash / sing-box nodes that other clients (Shadowrocket,
// v2rayN, Xray) accept also start in sing-box, instead of turning into "initialize outbound"
// placeholders. Applied when a subscription is parsed and again when the config is built, so
// profiles parsed by an older core are fixed without updating the subscription.
//
// Main case: Cloudflare Workers/Pages nodes (edgetunnel, CF-Workers-SUB) with ECH turned on
// put Xray's echConfigList into the link, e.g.
//   ech=cloudflare-ech.com+https://dns.alidns.com/dns-query
// which is "query the ECH config of cloudflare-ech.com through that DNS server", not a PEM
// config; it used to be wrapped into a PEM block and failed with "invalid ECH configs pem".

import (
	"encoding/base64"
	"encoding/pem"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	echPEMBegin = "-----BEGIN ECH CONFIGS-----"
	echPEMEnd   = "-----END ECH CONFIGS-----"
)

// museFixOutbounds repairs, in place, option values that sing-box rejects when it creates
// the outbound but that other clients accept or ignore.
func museFixOutbounds(outbounds []option.Outbound) {
	for i := range outbounds {
		museFixOutbound(&outbounds[i])
	}
}

func museFixOutbound(outbound *option.Outbound) {
	if outbound.Options == nil {
		return
	}
	var transport *option.V2RayTransportOptions
	switch opts := outbound.Options.(type) {
	case *option.VLESSOutboundOptions:
		transport = opts.Transport
		// VLESS has no cipher: "auto"/"aes-128-gcm"/"zero" in some links mean plain VLESS.
		// Real VLESS encryption strings (mlkem768x25519plus.native....) contain dots.
		if enc := strings.TrimSpace(opts.Encryption); enc != "" && (strings.EqualFold(enc, "none") || !strings.Contains(enc, ".")) {
			opts.Encryption = ""
		}
		opts.Flow = strings.TrimSpace(opts.Flow)
		if opts.Flow != "" && transport != nil && transport.Type != "" {
			// xtls-rprx-vision only works on raw TCP; Xray ignores it on ws/grpc/...
			opts.Flow = ""
		}
		if opts.PacketEncoding != nil {
			switch *opts.PacketEncoding {
			case "", "xudp", "packetaddr":
			default:
				xudp := "xudp"
				opts.PacketEncoding = &xudp
			}
		}
	case *option.VMessOutboundOptions:
		transport = opts.Transport
		switch opts.PacketEncoding {
		case "", "xudp", "packetaddr":
		default:
			opts.PacketEncoding = "xudp"
		}
	case *option.TrojanOutboundOptions:
		transport = opts.Transport
	}
	museFixWebsocketEarlyData(transport)
	if wrapper, ok := outbound.Options.(option.OutboundTLSOptionsWrapper); ok {
		if tlsOptions := wrapper.TakeOutboundTLSOptions(); tlsOptions != nil && tlsOptions.Enabled {
			museFixTLS(tlsOptions, transport)
		}
	}
}

func museFixTLS(tlsOptions *option.OutboundTLSOptions, transport *option.V2RayTransportOptions) {
	reality := tlsOptions.Reality != nil && tlsOptions.Reality.Enabled

	if tlsOptions.UTLS != nil && tlsOptions.UTLS.Enabled {
		tlsOptions.UTLS.Fingerprint = museUTLSFingerprint(tlsOptions.UTLS.Fingerprint)
	}

	// An empty SNI makes sing-box send the server address; for a Cloudflare IP that is an IP
	// SNI the edge rejects. Clients use the Host header instead.
	if tlsOptions.ServerName == "" && !tlsOptions.DisableSNI && !reality {
		if host := museTransportHost(transport); host != "" {
			tlsOptions.ServerName = host
		}
	}

	if tlsOptions.ECH != nil {
		if reality {
			// sing-box refuses Reality together with ECH; Reality nodes never use ECH.
			tlsOptions.ECH = nil
		} else if tlsOptions.ECH.Enabled {
			museFixECH(tlsOptions.ECH)
		}
	}
}

// museUTLSFingerprint maps fingerprint names used by Xray, Clash and share links to the
// names sing-box knows; unknown names fall back to chrome (the default) instead of failing.
func museUTLSFingerprint(fp string) string {
	name := strings.ToLower(strings.TrimSpace(fp))
	name = strings.TrimSuffix(name, "_auto")
	switch name {
	case "", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized",
		"chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk":
		return name
	case "randomizednoalpn", "randomized_noalpn", "randomizedalpn", "hellorandomized":
		return "randomized"
	case "microsoft", "msedge":
		return "edge"
	case "okhttp", "android_11_okhttp":
		return "android"
	case "iphone", "ipad":
		return "ios"
	case "unsafe", "none", "golang", "go":
		return "chrome"
	default:
		return "chrome"
	}
}

func museTransportHost(transport *option.V2RayTransportOptions) string {
	if transport == nil {
		return ""
	}
	pick := func(headers badoption.HTTPHeader) string {
		for key, values := range headers {
			if strings.EqualFold(key, "host") && len(values) > 0 {
				return strings.TrimSpace(values[0])
			}
		}
		return ""
	}
	var host string
	switch transport.Type {
	case C.V2RayTransportTypeWebsocket:
		host = pick(transport.WebsocketOptions.Headers)
	case C.V2RayTransportTypeHTTPUpgrade:
		host = strings.TrimSpace(transport.HTTPUpgradeOptions.Host)
		if host == "" {
			host = pick(transport.HTTPUpgradeOptions.Headers)
		}
	case C.V2RayTransportTypeHTTP:
		if len(transport.HTTPOptions.Host) > 0 {
			host = strings.TrimSpace(transport.HTTPOptions.Host[0])
		}
	case C.V2RayTransportTypeXHTTP:
		host = strings.TrimSpace(transport.XHTTPOptions.Host)
	}
	if h, _, ok := strings.Cut(host, ","); ok {
		host = strings.TrimSpace(h)
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ""
	}
	return host
}

// museFixWebsocketEarlyData turns "/path?ed=2560" (Xray/Clash style 0-RTT) into sing-box's
// max_early_data + Sec-WebSocket-Protocol, like ray2sing does for share links.
func museFixWebsocketEarlyData(transport *option.V2RayTransportOptions) {
	if transport == nil || transport.Type != C.V2RayTransportTypeWebsocket {
		return
	}
	ws := &transport.WebsocketOptions
	if ws.MaxEarlyData != 0 || !strings.Contains(ws.Path, "ed=") {
		return
	}
	pathURL, err := url.Parse(ws.Path)
	if err != nil {
		return
	}
	query := pathURL.Query()
	ed, err := strconv.ParseUint(query.Get("ed"), 10, 32)
	if err != nil || ed == 0 {
		return
	}
	query.Del("ed")
	pathURL.RawQuery = query.Encode()
	ws.Path = pathURL.String()
	if ws.Path == "" {
		ws.Path = "/"
	}
	ws.MaxEarlyData = uint32(ed)
	if ws.EarlyDataHeaderName == "" {
		ws.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
	}
}

// museFixECH accepts every form of Xray's echConfigList:
//   - a base64 ECHConfigList (with or without PEM armour)       -> config
//   - "domain+dnsServer", e.g. cloudflare-ech.com+https://...  -> query_server_name = domain
//   - "dnsServer" only, e.g. https://1.1.1.1/dns-query          -> query the node's own SNI
//   - "domain"                                                 -> query_server_name = domain
//
// Without a config sing-box looks the ECH config up in DNS when it connects.
func museFixECH(ech *option.OutboundECHOptions) {
	if len(ech.Config) == 0 {
		return
	}
	joined := strings.Join(ech.Config, "\n")
	if block, rest := pem.Decode([]byte(joined)); block != nil && block.Type == "ECH CONFIGS" && len(strings.TrimSpace(string(rest))) == 0 {
		return
	}
	raw := strings.TrimSpace(strings.NewReplacer(echPEMBegin, "", echPEMEnd, "").Replace(joined))
	raw = strings.Join(strings.Fields(raw), "")
	ech.Config = nil
	if raw == "" {
		return
	}
	if strings.Contains(raw, "%") {
		// PathUnescape: a "+" is the domain/DNS separator here, not an escaped space
		if unescaped, err := url.PathUnescape(raw); err == nil {
			raw = unescaped
		}
	}
	if domain, _, ok := strings.Cut(raw, "+"); ok && !strings.Contains(domain, "://") {
		if museLooksLikeDomain(domain) && ech.QueryServerName == "" {
			ech.QueryServerName = domain
		}
		return
	}
	if strings.Contains(raw, "://") {
		return
	}
	if museLooksLikeDomain(raw) {
		if ech.QueryServerName == "" {
			ech.QueryServerName = raw
		}
		return
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := enc.DecodeString(raw); err == nil && len(data) > 4 {
			ech.Config = badoption.Listable[string]{string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: data}))}
			return
		}
	}
	// not usable: keep ECH on and look the config up by the node's SNI
}

func museLooksLikeDomain(s string) bool {
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") || strings.ContainsAny(s, "/:@ ") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// museECHQueryDomains lists the names whose ECH (HTTPS) records sing-box will look up for
// the given outbounds, so the lookup can go to the direct DNS: the default remote DNS is
// reached through the proxy itself, which needs the ECH config first.
func museECHQueryDomains(outbounds []option.Outbound) []string {
	seen := map[string]bool{}
	var names []string
	for _, outbound := range outbounds {
		wrapper, ok := outbound.Options.(option.OutboundTLSOptionsWrapper)
		if !ok {
			continue
		}
		tlsOptions := wrapper.TakeOutboundTLSOptions()
		if tlsOptions == nil || !tlsOptions.Enabled || tlsOptions.ECH == nil || !tlsOptions.ECH.Enabled ||
			len(tlsOptions.ECH.Config) > 0 || tlsOptions.ECH.ConfigPath != "" {
			continue
		}
		name := tlsOptions.ECH.QueryServerName
		if name == "" {
			name = tlsOptions.ServerName
		}
		if name == "" {
			if server, ok := outbound.Options.(option.ServerOptionsWrapper); ok {
				name = server.TakeServerOptions().Server
			}
		}
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if !museLooksLikeDomain(name) || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

func museECHDNSRules(outbounds []option.Outbound, hopt *HiddifyOptions) []option.DefaultDNSRule {
	names := museECHQueryDomains(outbounds)
	if len(names) == 0 {
		return nil
	}
	return []option.DefaultDNSRule{{
		RawDefaultDNSRule: option.RawDefaultDNSRule{
			QueryType: badoption.Listable[option.DNSQueryType]{option.DNSQueryType(65)}, // HTTPS
			Domain:    names,
		},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server: DNSMultiDirectTag,
			},
		},
	}}
}
