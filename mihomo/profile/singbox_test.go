package profile

import (
	"fmt"
	"os"
	"reflect"
	"testing"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The same nodes reach this core either as share links (mapped by mihomo's own converter) or
// as the main core's stored JSON (mapped by the table in singbox.go); both must give the same
// connection settings.
func TestSingBoxJSONMatchesShareLinks(t *testing.T) {
	fromLinks, err := Parse(mustRead(t, "testdata/pair_links.txt"))
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := Parse(mustRead(t, "testdata/pair_singbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fromJSON.Kind != KindSingBoxJSON || len(fromJSON.Unsupported) != 0 {
		t.Fatalf("kind %v unsupported %v", fromJSON.Kind, fromJSON.Unsupported)
	}
	if len(fromLinks.Proxies) != len(fromJSON.Proxies) {
		t.Fatalf("links %d nodes, JSON %d nodes", len(fromLinks.Proxies), len(fromJSON.Proxies))
	}
	// keys that decide where and how the node connects
	keys := []string{"name", "type", "server", "port", "uuid", "password", "flow", "network", "servername", "sni",
		"skip-cert-verify", "client-fingerprint", "reality-opts", "ws-opts", "grpc-opts", "obfs", "obfs-password",
		"congestion-controller", "alpn"}
	for i := range fromLinks.Proxies {
		l, j := fromLinks.Proxies[i], fromJSON.Proxies[i]
		for _, k := range keys {
			lv, lok := l[k]
			jv, jok := j[k]
			if !lok && !jok {
				continue
			}
			// defaults one side writes out and the other leaves implied
			if (k == "network" && (lv == "tcp" || jv == "tcp") && (!lok || !jok)) ||
				(k == "skip-cert-verify" && lv != true && jv != true) ||
				(k == "client-fingerprint" && (!lok || !jok)) ||
				((k == "alpn" || k == "grpc-opts" || k == "reality-opts") && (!lok || !jok)) {
				continue
			}
			if k == "ws-opts" && lok && jok {
				// the link converter adds a browser User-Agent header; compare path and Host
				lw, jw := lv.(map[string]any), jv.(map[string]any)
				lh, _ := lw["headers"].(map[string]any)
				jh, _ := jw["headers"].(map[string]any)
				if fmt.Sprint(lw["path"]) != fmt.Sprint(jw["path"]) || fmt.Sprint(lh["Host"]) != fmt.Sprint(jh["Host"]) {
					t.Errorf("%s: ws-opts link=%v json=%v", l["name"], lv, jv)
				}
				continue
			}
			if fmt.Sprint(norm(lv)) != fmt.Sprint(norm(jv)) {
				t.Errorf("%s: %s link=%v json=%v", l["name"], k, lv, jv)
			}
		}
	}
}

// norm makes values from the two sources comparable (ints vs strings, nested maps).
func norm(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]string{}
		for k, val := range x {
			out[k] = fmt.Sprint(norm(val))
		}
		return out
	case []any:
		out := make([]string, len(x))
		for i, val := range x {
			out[i] = fmt.Sprint(val)
		}
		return out
	case []string:
		return x
	case float64:
		return int(x)
	}
	return v
}

func TestSingBoxMappingTable(t *testing.T) {
	cases := []struct {
		name string
		in   sbObj
		want map[string]any
	}{
		{"vmess ws tls", sbObj{"type": "vmess", "server": "v.example.com", "server_port": 443.0, "uuid": "u", "security": "aes-128-gcm", "alter_id": 0.0,
			"tls":       sbObj{"enabled": true, "server_name": "v.example.com", "insecure": true},
			"transport": sbObj{"type": "ws", "path": "/p", "headers": sbObj{"Host": "h.example.com"}, "max_early_data": 2048.0},
			"multiplex": sbObj{"enabled": true, "protocol": "smux", "max_streams": 4.0}},
			map[string]any{"type": "vmess", "server": "v.example.com", "port": 443, "uuid": "u", "alterId": 0, "cipher": "aes-128-gcm", "udp": true,
				"tls": true, "servername": "v.example.com", "skip-cert-verify": true, "network": "ws",
				"ws-opts": map[string]any{"path": "/p", "headers": map[string]any{"Host": "h.example.com"}, "max-early-data": 2048, "early-data-header-name": "Sec-WebSocket-Protocol"},
				"smux":    map[string]any{"enabled": true, "protocol": "smux", "max-streams": 4}}},
		{"shadowsocks obfs", sbObj{"type": "shadowsocks", "server": "s.example.com", "server_port": 8388.0, "method": "chacha20-ietf-poly1305", "password": "p",
			"plugin": "obfs-local", "plugin_opts": "obfs=tls;obfs-host=bing.com"},
			map[string]any{"type": "ss", "server": "s.example.com", "port": 8388, "cipher": "chacha20-ietf-poly1305", "password": "p", "udp": true,
				"plugin": "obfs", "plugin-opts": map[string]any{"mode": "tls", "host": "bing.com"}}},
		{"shadowsocks v2ray-plugin", sbObj{"type": "shadowsocks", "server": "s.example.com", "server_port": 443.0, "method": "aes-256-gcm", "password": "p",
			"plugin": "v2ray-plugin", "plugin_opts": "mode=websocket;host=w.example.com;path=/x;tls"},
			map[string]any{"type": "ss", "server": "s.example.com", "port": 443, "cipher": "aes-256-gcm", "password": "p", "udp": true,
				"plugin": "v2ray-plugin", "plugin-opts": map[string]any{"mode": "websocket", "host": "w.example.com", "path": "/x", "tls": true}}},
		{"hysteria2 hop", sbObj{"type": "hysteria2", "server": "h.example.com", "server_port": 443.0, "password": "p", "up_mbps": 50.0, "down_mbps": 200.0,
			"server_ports": []any{"20000:30000"}, "tls": sbObj{"enabled": true, "server_name": "h.example.com", "alpn": []any{"h3"}}},
			map[string]any{"type": "hysteria2", "server": "h.example.com", "port": 443, "password": "p", "up": "50 Mbps", "down": "200 Mbps",
				"ports": "20000-30000", "sni": "h.example.com", "alpn": []string{"h3"}}},
		{"vless httpupgrade + detour", sbObj{"type": "vless", "server": "x.example.com", "server_port": 80.0, "uuid": "u", "detour": "front",
			"transport": sbObj{"type": "httpupgrade", "path": "/up", "host": "x.example.com"}},
			map[string]any{"type": "vless", "server": "x.example.com", "port": 80, "uuid": "u", "udp": true, "dialer-proxy": "front", "network": "ws",
				"ws-opts": map[string]any{"path": "/up", "v2ray-http-upgrade": true, "headers": map[string]any{"Host": "x.example.com"}}}},
		{"wireguard endpoint", sbObj{"type": "wireguard", "address": []any{"172.16.0.2/32", "fd00::2/128"}, "private_key": "priv", "mtu": 1280.0,
			"peers": []any{sbObj{"address": "w.example.com", "port": 51820.0, "public_key": "pub", "reserved": []any{1.0, 2.0, 3.0}}}},
			map[string]any{"type": "wireguard", "udp": true, "private-key": "priv", "mtu": 1280, "ip": "172.16.0.2", "ipv6": "fd00::2",
				"server": "w.example.com", "port": 51820, "public-key": "pub", "reserved": []any{1.0, 2.0, 3.0}}},
		{"wireguard legacy outbound", sbObj{"type": "wireguard", "server": "w.example.com", "server_port": 2408.0, "local_address": []any{"172.16.0.2/32"},
			"private_key": "priv", "peer_public_key": "pub", "pre_shared_key": "psk"},
			map[string]any{"type": "wireguard", "udp": true, "private-key": "priv", "ip": "172.16.0.2", "server": "w.example.com", "port": 2408,
				"public-key": "pub", "pre-shared-key": "psk"}},
		{"socks5", sbObj{"type": "socks", "server": "127.0.0.1", "server_port": 1080.0, "username": "u", "password": "p"},
			map[string]any{"type": "socks5", "server": "127.0.0.1", "port": 1080, "username": "u", "password": "p", "udp": true}},
		{"http h1 tls", sbObj{"type": "http", "server": "p.example.com", "server_port": 443.0, "tls": sbObj{"enabled": true, "server_name": "p.example.com"}},
			map[string]any{"type": "http", "server": "p.example.com", "port": 443, "tls": true, "sni": "p.example.com"}},
		{"ssh", sbObj{"type": "ssh", "server": "s.example.com", "server_port": 22.0, "user": "me", "password": "p"},
			map[string]any{"type": "ssh", "server": "s.example.com", "port": 22, "username": "me", "password": "p"}},
		{"tuic", sbObj{"type": "tuic", "server": "t.example.com", "server_port": 443.0, "uuid": "u", "password": "p", "udp_relay_mode": "quic", "zero_rtt_handshake": true},
			map[string]any{"type": "tuic", "server": "t.example.com", "port": 443, "uuid": "u", "password": "p", "udp-relay-mode": "quic", "reduce-rtt": true, "udp": true}},
	}
	for _, c := range cases {
		got, reason, detail := MapSingBoxOutbound(c.in)
		if got == nil {
			t.Errorf("%s: not mapped (%s %s)", c.name, reason, detail)
			continue
		}
		if fmt.Sprint(norm(got)) != fmt.Sprint(norm(c.want)) {
			t.Errorf("%s:\n got  %v\n want %v", c.name, got, c.want)
		}
	}
}

func TestSingBoxUnsupportedKeptWithReason(t *testing.T) {
	js := `[
	  {"type":"naive","tag":"N","server":"n.example.com","server_port":443},
	  {"type":"tor","tag":"Tor"},
	  {"type":"shadowtls","tag":"STLS","server":"s.example.com","server_port":443},
	  {"type":"vless","tag":"QUIC","server":"q.example.com","server_port":443,"uuid":"u","transport":{"type":"quic"}},
	  {"type":"vmess","tag":"VR","server":"v.example.com","server_port":443,"uuid":"u","tls":{"enabled":true,"reality":{"enabled":true}}},
	  {"type":"shadowsocks","tag":"KCP","server":"k.example.com","server_port":1,"method":"aes-128-gcm","password":"p","plugin":"kcptun"},
	  {"type":"wireguard","tag":"WG2","private_key":"k","peers":[{"address":"a","port":1,"public_key":"p"},{"address":"b","port":2,"public_key":"q"}]},
	  {"type":"vless","tag":"NoPort","server":"x.example.com","uuid":"u"},
	  {"type":"trojan","tag":"Chained","server":"c.example.com","server_port":443,"password":"p","detour":"N"},
	  {"type":"trojan","tag":"OK","server":"o.example.com","server_port":443,"password":"p","tls":{"enabled":true}},
	  "junk"
	]`
	p, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Proxies) != 1 || p.Proxies[0]["name"] != "OK" {
		t.Fatalf("proxies %v", p.Proxies)
	}
	got := map[string]string{}
	for _, u := range p.Unsupported {
		got[u.Name] = u.Reason
	}
	want := map[string]string{
		"N": ReasonUnsupportedProtocol, "Tor": ReasonUnsupportedProtocol, "STLS": ReasonUnsupportedProtocol,
		"QUIC": ReasonUnsupportedProtocol, "VR": ReasonUnsupportedProtocol, "KCP": ReasonUnsupportedProtocol,
		"WG2": ReasonUnsupportedProtocol, "NoPort": ReasonInvalid, "Chained": ReasonInvalid, "#11": ReasonInvalid,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unsupported\n got  %v\n want %v", got, want)
	}
}

func TestSingBoxJSONShapes(t *testing.T) {
	single := `{"type":"trojan","tag":"one","server":"o.example.com","server_port":443,"password":"p"}`
	p, err := Parse([]byte(single))
	if err != nil || len(p.Proxies) != 1 || p.Proxies[0]["name"] != "one" {
		t.Fatalf("single: %v %v", p, err)
	}
	withEndpoints := `{"outbounds":[{"type":"direct","tag":"direct"}],"endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"k","peers":[{"address":"w.example.com","port":51820,"public_key":"p"}]}]}`
	p, err = Parse([]byte(withEndpoints))
	if err != nil || len(p.Proxies) != 1 || p.Proxies[0]["type"] != "wireguard" {
		t.Fatalf("endpoints: %v %v", p, err)
	}
	dup := `[{"type":"trojan","tag":"A","server":"a","server_port":1,"password":"p"},{"type":"trojan","tag":"A","server":"b","server_port":1,"password":"p"}]`
	p, err = Parse([]byte(dup))
	if err != nil || p.Proxies[1]["name"] != "A-01" {
		t.Fatalf("dup names: %v %v", p.Proxies, err)
	}
	comments := "/* c */ [ // x\n {\"type\":\"trojan\",\"tag\":\"a//b\",\"server\":\"a\",\"server_port\":1,\"password\":\"p\"}]"
	p, err = Parse([]byte(comments))
	if err != nil || p.Proxies[0]["name"] != "a//b" {
		t.Fatalf("comments: %v %v", p, err)
	}
}
