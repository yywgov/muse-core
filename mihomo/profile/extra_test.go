package profile

import (
	"strings"
	"testing"
)

// 穿云 1.9.0: SIP008 and WireGuard .conf subscriptions, as the main core reads them.
func TestSIP008(t *testing.T) {
	doc := `{"version":1,"servers":[
	 {"id":"1","remarks":"香港 01","server":"hk.example.com","server_port":8388,"password":"p1","method":"aes-256-gcm"},
	 {"remarks":"obfs","server":"o.example.com","server_port":"443","password":"p2","method":"chacha20-ietf-poly1305","plugin":"obfs-local","plugin_opts":"obfs=tls;obfs-host=www.bing.com"},
	 {"remarks":"v2","server":"v.example.com","server_port":443,"password":"p3","method":"aes-128-gcm","plugin":"v2ray-plugin","plugin_opts":"tls;host=v.example.com;path=/ws"},
	 {"remarks":"quic","server":"q.example.com","server_port":443,"password":"p4","method":"aes-128-gcm","plugin":"v2ray-plugin","plugin_opts":"mode=quic"},
	 {"remarks":"bad","server":"","server_port":1,"password":"x","method":"aes-128-gcm"}
	]}`
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindSIP008 || p.Kind.String() != "sip008" {
		t.Errorf("kind %v", p.Kind)
	}
	if len(p.Proxies) != 3 || len(p.Unsupported) != 2 {
		t.Fatalf("proxies %d unsupported %v", len(p.Proxies), p.Unsupported)
	}
	a := p.Proxies[0]
	if a["name"] != "香港 01" || a["type"] != "ss" || a["server"] != "hk.example.com" || a["port"] != 8388 || a["cipher"] != "aes-256-gcm" || a["password"] != "p1" {
		t.Errorf("first %v", a)
	}
	o := p.Proxies[1]
	if o["port"] != 443 || o["plugin"] != "obfs" || o["plugin-opts"].(map[string]any)["mode"] != "tls" || o["plugin-opts"].(map[string]any)["host"] != "www.bing.com" {
		t.Errorf("obfs %v", o)
	}
	v := p.Proxies[2]["plugin-opts"].(map[string]any)
	if p.Proxies[2]["plugin"] != "v2ray-plugin" || v["mode"] != "websocket" || v["tls"] != true || v["path"] != "/ws" {
		t.Errorf("v2ray %v", p.Proxies[2])
	}
	if p.Unsupported[0].Name != "quic" || p.Unsupported[0].Reason != ReasonUnsupportedProtocol {
		t.Errorf("quic %v", p.Unsupported[0])
	}
	// a sing-box document with a "servers" key elsewhere is still sing-box
	if _, ok := isSIP008([]byte(`{"outbounds":[],"servers":[{"server":"a"}]}`)); ok {
		t.Error("sing-box JSON taken for SIP008")
	}
}

func TestWireGuardConf(t *testing.T) {
	conf := `# Name = 家里
[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=
Address = 10.8.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI=
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrMTI=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = wg.example.com:51820
PersistentKeepalive = 25
`
	p, err := Parse([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindWireGuardConf || len(p.Proxies) != 1 || len(p.Unsupported) != 0 {
		t.Fatalf("%v %v %v", p.Kind, p.Proxies, p.Unsupported)
	}
	w := p.Proxies[0]
	if w["name"] != "家里" || w["type"] != "wireguard" || w["server"] != "wg.example.com" || w["port"] != 51820 ||
		w["ip"] != "10.8.0.2/32" || w["ipv6"] != "fd00::2/128" || w["mtu"] != 1280 || w["persistent-keepalive"] != 25 {
		t.Errorf("wg %v", w)
	}
	if w["pre-shared-key"] == nil || len(w["allowed-ips"].([]string)) != 2 || len(w["dns"].([]string)) != 2 {
		t.Errorf("wg lists %v", w)
	}
	// unnamed: named after the endpoint
	p, _ = Parse([]byte(strings.Replace(conf, "# Name = 家里\n", "", 1)))
	if p.Proxies[0]["name"] != "WireGuard wg.example.com" {
		t.Errorf("name %v", p.Proxies[0]["name"])
	}
	// broken: kept as unavailable, not dropped
	p, err = Parse([]byte("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = a:1\n"))
	if err != nil || len(p.Proxies) != 0 || len(p.Unsupported) != 1 || p.Unsupported[0].Reason != ReasonInvalid {
		t.Errorf("broken %v %v", p, err)
	}
}

func TestFakeTCPHysteriaNotBuilt(t *testing.T) {
	y := "proxies:\n  - {name: a, type: hysteria, server: h.example.com, port: 443, protocol: faketcp, auth-str: x}\n  - {name: b, type: hysteria, server: h.example.com, port: 443, protocol: udp, auth-str: x}\n"
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Proxies) != 1 || len(p.Unsupported) != 1 || p.Unsupported[0].Reason != ReasonNotBuilt {
		t.Errorf("%v %v", p.Proxies, p.Unsupported)
	}
	if !strings.Contains(BuildTags, "no_fake_tcp") {
		t.Error("build tags")
	}
}
