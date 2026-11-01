package profile

// 穿云 1.9.0: two more subscription formats the main core reads, so 兼容内核 on Windows (where it
// parses subscriptions itself) takes the same subscriptions as on Android:
//   - SIP008 (Shadowsocks online config: {"version":1,"servers":[...]})
//   - a WireGuard .conf ([Interface] + [Peer] sections)
// Nodes are converted to mihomo proxies; what cannot be converted is kept as Unsupported.

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// KindSIP008 and KindWireGuardConf extend Kind.
const (
	KindSIP008 Kind = iota + 100
	KindWireGuardConf
)

func init() {
	extraKindNames[KindSIP008] = "sip008"
	extraKindNames[KindWireGuardConf] = "wireguard-conf"
}

var extraKindNames = map[Kind]string{}

type sip008 struct {
	Version json.RawMessage `json:"version"`
	Servers []sip008Server  `json:"servers"`
}

type sip008Server struct {
	ID         string          `json:"id"`
	Remarks    string          `json:"remarks"`
	Server     string          `json:"server"`
	ServerPort json.RawMessage `json:"server_port"`
	Password   string          `json:"password"`
	Method     string          `json:"method"`
	Plugin     string          `json:"plugin"`
	PluginOpts string          `json:"plugin_opts"`
}

// isSIP008 reports whether a JSON object is a SIP008 document (servers, no sing-box outbounds).
func isSIP008(j []byte) (*sip008, bool) {
	var probe map[string]json.RawMessage
	if json.Unmarshal(j, &probe) != nil {
		return nil, false
	}
	if _, ok := probe["servers"]; !ok {
		return nil, false
	}
	if _, ok := probe["outbounds"]; ok {
		return nil, false
	}
	var doc sip008
	if json.Unmarshal(j, &doc) != nil || len(doc.Servers) == 0 {
		return nil, false
	}
	return &doc, true
}

// isSIP008List reports whether a JSON array is a bare SIP008 server list (objects with server_port).
func isSIP008List(j []byte) (*sip008, bool) {
	var probe []map[string]json.RawMessage
	if json.Unmarshal(j, &probe) != nil || len(probe) == 0 {
		return nil, false
	}
	if _, ok := probe[0]["server_port"]; !ok {
		return nil, false
	}
	if _, ok := probe[0]["type"]; ok { // a sing-box outbound list, not SIP008
		return nil, false
	}
	var doc sip008
	if json.Unmarshal(append(append([]byte(`{"servers":`), j...), '}'), &doc) != nil || len(doc.Servers) == 0 {
		return nil, false
	}
	return &doc, true
}

func parseSIP008(doc *sip008) (*Profile, error) {
	p := &Profile{Kind: KindSIP008}
	names := map[string]int{}
	for _, s := range doc.Servers {
		name := strings.TrimSpace(s.Remarks)
		if name == "" {
			name = s.Server
		}
		port, _ := strconv.Atoi(strings.Trim(string(s.ServerPort), `" `))
		if s.Server == "" || port <= 0 || port > 65535 || s.Method == "" {
			p.Unsupported = append(p.Unsupported, Unsupported{Name: name, Type: "ss", Reason: ReasonInvalid, Detail: "missing server, port or method"})
			continue
		}
		px := map[string]any{
			"name": uniqueName(names, name), "type": "ss", "server": s.Server, "port": port,
			"cipher": s.Method, "password": s.Password, "udp": true,
		}
		if s.Plugin != "" {
			plugin, opts, ok := ssPlugin(s.Plugin, s.PluginOpts)
			if !ok {
				p.Unsupported = append(p.Unsupported, Unsupported{Name: name, Type: "ss", Reason: ReasonUnsupportedProtocol, Detail: "plugin " + s.Plugin})
				continue
			}
			px["plugin"] = plugin
			px["plugin-opts"] = opts
		}
		p.Proxies = append(p.Proxies, px)
	}
	if len(p.Proxies) == 0 && len(p.Unsupported) == 0 {
		return nil, ErrEmpty
	}
	return p, nil
}

// ssPlugin maps a SIP003 plugin (name + "k=v;flag" options) to mihomo's plugin + plugin-opts.
func ssPlugin(name, raw string) (string, map[string]any, bool) {
	kv := map[string]string{}
	flags := map[string]bool{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		} else {
			flags[part] = true
		}
	}
	switch strings.ToLower(name) {
	case "obfs-local", "simple-obfs", "obfs":
		mode := kv["obfs"]
		if mode == "" {
			mode = "http"
		}
		if mode != "http" && mode != "tls" {
			return "", nil, false
		}
		opts := map[string]any{"mode": mode}
		if h := kv["obfs-host"]; h != "" {
			opts["host"] = h
		}
		return "obfs", opts, true
	case "v2ray-plugin":
		mode := kv["mode"]
		if mode == "" {
			mode = "websocket"
		}
		if mode != "websocket" {
			return "", nil, false // quic mode is not implemented by mihomo
		}
		opts := map[string]any{"mode": "websocket"}
		if flags["tls"] {
			opts["tls"] = true
		}
		if h := kv["host"]; h != "" {
			opts["host"] = h
		}
		if path := kv["path"]; path != "" {
			opts["path"] = path
		}
		if flags["mux"] || kv["mux"] == "true" {
			opts["mux"] = true
		}
		return "v2ray-plugin", opts, true
	}
	return "", nil, false
}

// isWireGuardConf reports whether the text looks like a WireGuard .conf.
func isWireGuardConf(text []byte) bool {
	s := strings.ToLower(string(text))
	return strings.Contains(s, "[interface]") && strings.Contains(s, "[peer]")
}

type wgPeer struct {
	publicKey, preShared, endpoint string
	allowed                        []string
	keepalive                      int
	reserved                       []any
}

func splitList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func parseWireGuardConf(text []byte) (*Profile, error) {
	var (
		section          string
		privateKey, name string
		addrs, dns       []string
		mtu              int
		peers            []*wgPeer
		cur              *wgPeer
	)
	for _, raw := range strings.Split(string(text), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			// "# Name = xxx" (some exporters) names the node
			c := strings.TrimSpace(strings.TrimLeft(line, "#;"))
			if k, v, ok := strings.Cut(c, "="); ok && strings.EqualFold(strings.TrimSpace(k), "name") && name == "" {
				name = strings.TrimSpace(v)
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				cur = &wgPeer{}
				peers = append(peers, cur)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				privateKey = v
			case "address":
				addrs = append(addrs, splitList(v)...)
			case "dns":
				dns = append(dns, splitList(v)...)
			case "mtu":
				mtu, _ = strconv.Atoi(v)
			}
		case "peer":
			switch k {
			case "publickey":
				cur.publicKey = v
			case "presharedkey":
				cur.preShared = v
			case "endpoint":
				cur.endpoint = v
			case "allowedips":
				cur.allowed = append(cur.allowed, splitList(v)...)
			case "persistentkeepalive":
				cur.keepalive, _ = strconv.Atoi(v)
			case "reserved":
				for _, b := range splitList(v) {
					if n, err := strconv.Atoi(b); err == nil {
						cur.reserved = append(cur.reserved, n)
					}
				}
			}
		}
	}
	p := &Profile{Kind: KindWireGuardConf}
	if name == "" && len(peers) > 0 {
		if host, _, err := net.SplitHostPort(peers[0].endpoint); err == nil {
			name = "WireGuard " + host
		}
	}
	if name == "" {
		name = "WireGuard"
	}
	bad := func(detail string) (*Profile, error) {
		p.Unsupported = append(p.Unsupported, Unsupported{Name: name, Type: "wireguard", Reason: ReasonInvalid, Detail: detail})
		return p, nil
	}
	if privateKey == "" {
		return bad("missing PrivateKey")
	}
	if len(peers) == 0 {
		return bad("missing [Peer]")
	}
	px := map[string]any{"name": name, "type": "wireguard", "private-key": privateKey, "udp": true}
	for _, a := range addrs {
		ip := a
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		parsed := net.ParseIP(ip)
		switch {
		case parsed == nil:
		case parsed.To4() != nil:
			if _, ok := px["ip"]; !ok {
				px["ip"] = a
			}
		default:
			if _, ok := px["ipv6"]; !ok {
				px["ipv6"] = a
			}
		}
	}
	if _, ok := px["ip"]; !ok {
		if _, ok6 := px["ipv6"]; !ok6 {
			return bad("missing Address")
		}
	}
	if mtu > 0 {
		px["mtu"] = mtu
	}
	if len(dns) > 0 {
		px["dns"] = dns
	}
	peerMap := func(pe *wgPeer) (map[string]any, bool) {
		host, portS, err := net.SplitHostPort(pe.endpoint)
		port, _ := strconv.Atoi(portS)
		if err != nil || host == "" || port <= 0 || pe.publicKey == "" {
			return nil, false
		}
		m := map[string]any{"server": host, "port": port, "public-key": pe.publicKey}
		if pe.preShared != "" {
			m["pre-shared-key"] = pe.preShared
		}
		if len(pe.allowed) > 0 {
			m["allowed-ips"] = pe.allowed
		}
		if len(pe.reserved) > 0 {
			m["reserved"] = pe.reserved
		}
		return m, true
	}
	if len(peers) == 1 {
		m, ok := peerMap(peers[0])
		if !ok {
			return bad("peer needs PublicKey and Endpoint host:port")
		}
		for k, v := range m {
			px[k] = v
		}
		if peers[0].keepalive > 0 {
			px["persistent-keepalive"] = peers[0].keepalive
		}
	} else {
		var list []any
		for _, pe := range peers {
			m, ok := peerMap(pe)
			if !ok {
				return bad("peer needs PublicKey and Endpoint host:port")
			}
			list = append(list, m)
			if pe.keepalive > 0 {
				px["persistent-keepalive"] = pe.keepalive
			}
		}
		px["peers"] = list
	}
	p.Proxies = append(p.Proxies, px)
	return p, nil
}
