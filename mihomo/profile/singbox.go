package profile

// The main core stores every profile as its own JSON (outbounds and endpoints, written by its
// subscription parser), so this core reads that format too: each outbound is mapped to a mihomo
// proxy by the table below. Types or options mihomo has no equivalent for are reported in
// Unsupported with the reason, never silently dropped or half-mapped.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// outbound types that are groups or built-ins in the main core; this core builds its own groups
var singboxSkipped = map[string]bool{
	"selector": true, "urltest": true, "direct": true, "block": true, "dns": true, "balancer": true,
}

// SingBoxTypes maps each main-core outbound type this core can run to its mihomo type.
var SingBoxTypes = map[string]string{
	"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss",
	"hysteria2": "hysteria2", "hysteria": "hysteria", "tuic": "tuic", "wireguard": "wireguard",
	"socks": "socks5", "http": "http", "ssh": "ssh", "anytls": "anytls",
}

type sbObj = map[string]any

func parseSingBoxJSON(content []byte) (*Profile, error) {
	var root any
	if err := json.Unmarshal(stripJSONComments(content), &root); err != nil {
		return nil, fmt.Errorf("profile: JSON: %w", err)
	}
	var outbounds []any
	switch v := root.(type) {
	case map[string]any:
		if v["outbounds"] == nil && v["endpoints"] == nil {
			outbounds = []any{v} // a single outbound
		} else {
			if o, ok := v["outbounds"].([]any); ok {
				outbounds = append(outbounds, o...)
			}
			if e, ok := v["endpoints"].([]any); ok {
				outbounds = append(outbounds, e...)
			}
		}
	case []any:
		outbounds = v
	}
	p := &Profile{Kind: KindSingBoxJSON}
	names := map[string]int{}
	for i, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok {
			p.Unsupported = append(p.Unsupported, Unsupported{Name: "#" + strconv.Itoa(i+1), Reason: ReasonInvalid, Detail: "not an object"})
			continue
		}
		typ := str(o, "type")
		tag := str(o, "tag")
		if singboxSkipped[typ] {
			continue
		}
		if tag == "" {
			tag = typ + "-" + strconv.Itoa(i+1)
		}
		px, reason, detail := MapSingBoxOutbound(o)
		if px == nil {
			p.Unsupported = append(p.Unsupported, Unsupported{Name: tag, Type: typ, Reason: reason, Detail: detail})
			continue
		}
		px["name"] = uniqueName(names, tag)
		p.Proxies = append(p.Proxies, px)
	}
	// a detour that points at a node this core cannot run makes the node unusable too
	have := map[string]bool{}
	for _, px := range p.Proxies {
		have[px["name"].(string)] = true
	}
	for i := 0; i < len(p.Proxies); i++ {
		if d, ok := p.Proxies[i]["dialer-proxy"].(string); ok && !have[d] {
			p.Reject(i, "detour "+d+" is not available")
			i--
		}
	}
	if len(p.Proxies) == 0 && len(p.Unsupported) == 0 {
		return nil, ErrEmpty
	}
	return p, nil
}

// MapSingBoxOutbound maps one main-core outbound. It returns the proxy (without "name"), or nil
// with a reason and detail when this core cannot run it.
func MapSingBoxOutbound(o sbObj) (px map[string]any, reason, detail string) {
	typ := str(o, "type")
	mt, ok := SingBoxTypes[typ]
	if !ok {
		return nil, ReasonUnsupportedProtocol, ""
	}
	if typ == "wireguard" {
		return mapWireGuard(o)
	}
	px = map[string]any{"type": mt, "server": str(o, "server"), "port": num(o, "server_port")}
	if px["server"] == "" || px["port"] == 0 {
		return nil, ReasonInvalid, "missing server or port"
	}
	if d := str(o, "detour"); d != "" {
		px["dialer-proxy"] = d
	}
	switch typ {
	case "vless":
		px["uuid"] = str(o, "uuid")
		px["udp"] = true
		if f := str(o, "flow"); f != "" {
			px["flow"] = f
		}
		if pe := str(o, "packet_encoding"); pe != "" {
			px["packet-encoding"] = pe
		}
	case "vmess":
		px["uuid"] = str(o, "uuid")
		px["alterId"] = num(o, "alter_id")
		px["cipher"] = orDefault(str(o, "security"), "auto")
		px["udp"] = true
		if b(o, "global_padding") {
			px["global-padding"] = true
		}
		if b(o, "authenticated_length") {
			px["authenticated-length"] = true
		}
		if pe := str(o, "packet_encoding"); pe != "" {
			px["packet-encoding"] = pe
		}
	case "trojan":
		px["password"] = str(o, "password")
		px["udp"] = true
	case "shadowsocks":
		px["cipher"] = str(o, "method")
		px["password"] = str(o, "password")
		px["udp"] = true
		if b(o, "udp_over_tcp") || obj(o, "udp_over_tcp") != nil {
			px["udp-over-tcp"] = true
		}
		if plugin := str(o, "plugin"); plugin != "" {
			name, opts, ok := mapSSPlugin(plugin, str(o, "plugin_opts"))
			if !ok {
				return nil, ReasonUnsupportedProtocol, "plugin " + plugin
			}
			px["plugin"], px["plugin-opts"] = name, opts
		}
	case "hysteria2":
		px["password"] = str(o, "password")
		if up := num(o, "up_mbps"); up > 0 {
			px["up"] = strconv.Itoa(up) + " Mbps"
		}
		if down := num(o, "down_mbps"); down > 0 {
			px["down"] = strconv.Itoa(down) + " Mbps"
		}
		if ob := obj(o, "obfs"); ob != nil && str(ob, "type") != "" {
			px["obfs"] = str(ob, "type")
			px["obfs-password"] = str(ob, "password")
		}
		if ports := strs(o, "server_ports"); len(ports) > 0 {
			px["ports"] = strings.ReplaceAll(strings.Join(ports, ","), ":", "-")
		}
	case "hysteria":
		px["auth-str"] = str(o, "auth_str")
		px["up"] = orDefault(str(o, "up"), strconv.Itoa(num(o, "up_mbps"))+" Mbps")
		px["down"] = orDefault(str(o, "down"), strconv.Itoa(num(o, "down_mbps"))+" Mbps")
		if ob := str(o, "obfs"); ob != "" {
			px["obfs"] = ob
		}
	case "tuic":
		px["uuid"] = str(o, "uuid")
		px["password"] = str(o, "password")
		if cc := str(o, "congestion_control"); cc != "" {
			px["congestion-controller"] = cc
		}
		if m := str(o, "udp_relay_mode"); m != "" {
			px["udp-relay-mode"] = m
		}
		if b(o, "zero_rtt_handshake") {
			px["reduce-rtt"] = true
		}
		px["udp"] = true
	case "socks":
		if v := str(o, "version"); v != "" && v != "5" {
			return nil, ReasonUnsupportedProtocol, "socks" + v
		}
		setIf(px, "username", str(o, "username"))
		setIf(px, "password", str(o, "password"))
		px["udp"] = true
	case "http":
		setIf(px, "username", str(o, "username"))
		setIf(px, "password", str(o, "password"))
	case "ssh":
		setIf(px, "username", orDefault(str(o, "user"), "root"))
		setIf(px, "password", str(o, "password"))
		setIf(px, "private-key", orDefault(str(o, "private_key"), strings.Join(strs(o, "private_key"), "\n")))
		if hk := strs(o, "host_key"); len(hk) > 0 {
			px["host-key"] = hk
		}
	case "anytls":
		px["password"] = str(o, "password")
		px["udp"] = true
	}
	if r, d := mapTLS(typ, obj(o, "tls"), px); r != "" {
		return nil, r, d
	}
	if r, d := mapTransport(obj(o, "transport"), px); r != "" {
		return nil, r, d
	}
	if mux := obj(o, "multiplex"); mux != nil && b(mux, "enabled") {
		if typ == "hysteria2" || typ == "hysteria" || typ == "tuic" {
			return nil, ReasonUnsupportedProtocol, "multiplex on " + typ
		}
		sm := map[string]any{"enabled": true, "protocol": orDefault(str(mux, "protocol"), "h2mux")}
		if n := num(mux, "max_streams"); n > 0 {
			sm["max-streams"] = n
		}
		if b(mux, "padding") {
			sm["padding"] = true
		}
		px["smux"] = sm
	}
	return px, "", ""
}

// TLS: sni key name differs per type in mihomo
func mapTLS(typ string, tls sbObj, px map[string]any) (string, string) {
	needsTLS := typ == "hysteria2" || typ == "hysteria" || typ == "tuic" || typ == "anytls" || typ == "trojan"
	if tls == nil || !b(tls, "enabled") {
		if needsTLS && typ != "trojan" {
			return "", "" // these always run TLS; mihomo uses the server name as SNI
		}
		if typ == "trojan" && tls != nil && !b(tls, "enabled") {
			return ReasonUnsupportedProtocol, "trojan without TLS"
		}
		return "", ""
	}
	if typ == "vless" || typ == "vmess" || typ == "socks" || typ == "http" {
		px["tls"] = true
	}
	sniKey := "sni"
	if typ == "vless" || typ == "vmess" {
		sniKey = "servername"
	}
	setIf(px, sniKey, str(tls, "server_name"))
	if b(tls, "insecure") {
		px["skip-cert-verify"] = true
	}
	if alpn := strs(tls, "alpn"); len(alpn) > 0 {
		px["alpn"] = alpn
	}
	if u := obj(tls, "utls"); u != nil && b(u, "enabled") {
		px["client-fingerprint"] = orDefault(str(u, "fingerprint"), "chrome")
	}
	if r := obj(tls, "reality"); r != nil && b(r, "enabled") {
		if typ != "vless" && typ != "trojan" {
			return ReasonUnsupportedProtocol, "reality on " + typ
		}
		ro := map[string]any{"public-key": str(r, "public_key")}
		setIf(ro, "short-id", str(r, "short_id"))
		px["reality-opts"] = ro
		if _, ok := px["client-fingerprint"]; !ok {
			px["client-fingerprint"] = "chrome"
		}
	}
	if e := obj(tls, "ech"); e != nil && b(e, "enabled") {
		eo := map[string]any{"enable": true}
		if cfg := strs(e, "config"); len(cfg) > 0 {
			eo["config"] = strings.Join(cfg, "")
		}
		px["ech-opts"] = eo
	}
	return "", ""
}

func mapTransport(t sbObj, px map[string]any) (string, string) {
	if t == nil {
		return "", ""
	}
	switch str(t, "type") {
	case "":
		return "", ""
	case "ws":
		px["network"] = "ws"
		ws := map[string]any{"path": orDefault(str(t, "path"), "/")}
		if h := hostHeader(t); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		if n := num(t, "max_early_data"); n > 0 {
			ws["max-early-data"] = n
			ws["early-data-header-name"] = orDefault(str(t, "early_data_header_name"), "Sec-WebSocket-Protocol")
		}
		px["ws-opts"] = ws
	case "httpupgrade":
		px["network"] = "ws"
		ws := map[string]any{"path": orDefault(str(t, "path"), "/"), "v2ray-http-upgrade": true}
		if h := orDefault(str(t, "host"), hostHeader(t)); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		px["ws-opts"] = ws
	case "grpc":
		px["network"] = "grpc"
		px["grpc-opts"] = map[string]any{"grpc-service-name": str(t, "service_name")}
	case "http":
		hosts := strs(t, "host")
		if _, tls := px["tls"]; tls || px["type"] == "trojan" {
			px["network"] = "h2"
			h2 := map[string]any{"path": orDefault(str(t, "path"), "/")}
			if len(hosts) > 0 {
				h2["host"] = hosts
			}
			px["h2-opts"] = h2
		} else {
			px["network"] = "http"
			ho := map[string]any{"path": []any{orDefault(str(t, "path"), "/")}}
			if len(hosts) > 0 {
				ho["headers"] = map[string]any{"Host": hosts}
			}
			if m := str(t, "method"); m != "" {
				ho["method"] = m
			}
			px["http-opts"] = ho
		}
	default:
		return ReasonUnsupportedProtocol, "transport " + str(t, "type")
	}
	return "", ""
}

func hostHeader(t sbObj) string {
	h := obj(t, "headers")
	if h == nil {
		return ""
	}
	for _, k := range []string{"Host", "host"} {
		if s := str(h, k); s != "" {
			return s
		}
		if l := strs(h, k); len(l) > 0 {
			return l[0]
		}
	}
	return ""
}

// shadowsocks plugins: obfs-local (simple-obfs) and v2ray-plugin, from the SIP003 option string
func mapSSPlugin(plugin, opts string) (string, map[string]any, bool) {
	kv := map[string]string{}
	flags := map[string]bool{}
	for _, part := range strings.Split(opts, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			kv[k] = v
		} else {
			flags[part] = true
		}
	}
	switch plugin {
	case "obfs-local", "simple-obfs", "obfs":
		return "obfs", map[string]any{"mode": orDefault(kv["obfs"], "http"), "host": kv["obfs-host"]}, true
	case "v2ray-plugin":
		o := map[string]any{"mode": orDefault(kv["mode"], "websocket"), "host": kv["host"], "path": orDefault(kv["path"], "/")}
		if flags["tls"] {
			o["tls"] = true
		}
		if flags["mux"] || kv["mux"] == "1" {
			o["mux"] = true
		}
		return "v2ray-plugin", o, true
	}
	return "", nil, false
}

func mapWireGuard(o sbObj) (map[string]any, string, string) {
	px := map[string]any{"type": "wireguard", "udp": true}
	setIf(px, "private-key", str(o, "private_key"))
	if mtu := num(o, "mtu"); mtu > 0 {
		px["mtu"] = mtu
	}
	addrs := strs(o, "local_address")
	if len(addrs) == 0 {
		addrs = strs(o, "address")
	}
	for _, a := range addrs {
		ip, _, _ := strings.Cut(a, "/")
		if strings.Contains(ip, ":") {
			px["ipv6"] = ip
		} else {
			px["ip"] = ip
		}
	}
	server, port, pub, psk := str(o, "server"), num(o, "server_port"), str(o, "peer_public_key"), str(o, "pre_shared_key")
	reserved := o["reserved"]
	if peers, ok := o["peers"].([]any); ok {
		if len(peers) != 1 {
			return nil, ReasonUnsupportedProtocol, "wireguard with " + strconv.Itoa(len(peers)) + " peers"
		}
		peer, _ := peers[0].(map[string]any)
		server, port, pub, psk = str(peer, "address"), num(peer, "port"), str(peer, "public_key"), str(peer, "pre_shared_key")
		reserved = peer["reserved"]
	}
	if server == "" || port == 0 || px["private-key"] == nil || pub == "" {
		return nil, ReasonInvalid, "missing server, port or keys"
	}
	px["server"], px["port"], px["public-key"] = server, port, pub
	setIf(px, "pre-shared-key", psk)
	if r, ok := reserved.([]any); ok && len(r) > 0 {
		px["reserved"] = r
	}
	if d := str(o, "detour"); d != "" {
		px["dialer-proxy"] = d
	}
	return px, "", ""
}

// --- small JSON helpers ---

func str(o sbObj, k string) string {
	switch v := o[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func num(o sbObj, k string) int {
	switch v := o[k].(type) {
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

func b(o sbObj, k string) bool { v, _ := o[k].(bool); return v }

func obj(o sbObj, k string) sbObj { v, _ := o[k].(map[string]any); return v }

func strs(o sbObj, k string) []string {
	switch v := o[k].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func setIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func orDefault(v, d string) string {
	if v == "" || v == "0 Mbps" {
		return d
	}
	return v
}

// stripJSONComments removes // and /* */ comments outside strings (the main core accepts them).
func stripJSONComments(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(in) && in[i+1] == '/' {
			for i < len(in) && in[i] != '\n' {
				i++
			}
			out = append(out, '\n')
			continue
		}
		if c == '/' && i+1 < len(in) && in[i+1] == '*' {
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, c)
	}
	return out
}
