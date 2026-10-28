package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yywgov/muse-core/mihomo/grpcsvc"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
	"github.com/yywgov/muse-core/mihomo/options"
	"github.com/yywgov/muse-core/mihomo/profile"
)

const yamlSub = `
proxies:
  - {name: HK, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: pw}
  - {name: JP, type: trojan, server: 127.0.0.1, port: 443, password: pw, sni: jp.example.com}
  - {name: Naive, type: naive, server: 127.0.0.1, port: 443}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK, JP, Naive]}
rules:
  - DOMAIN-SUFFIX,example.com,Proxy
  - DOMAIN,naive.example.com,Naive
  - MATCH,Proxy
`

const uriSub = "trojan://pw@127.0.0.1:443?sni=a.example.com#A\n" +
	"vless://11111111-2222-3333-4444-555555555555@127.0.0.1:443?encryption=none&security=tls&sni=b.example.com&type=grpc&serviceName=g#B\n" +
	"hysteria2://pw@127.0.0.1:443?sni=c.example.com#C\n" +
	"wireguard://k@127.0.0.1:51820#WG\n"

// What options.Build renders must load in mihomo itself, for both subscription kinds.
func TestBuiltConfigsParseInMihomo(t *testing.T) {
	m := &Mihomo{}
	m.SetHomeDir(t.TempDir())
	for name, sub := range map[string]string{"yaml": yamlSub, "uri": uriSub} {
		p, err := profile.Parse([]byte(sub))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s := options.Defaults()
		s.BypassLAN = true
		buf, err := options.Build(p, s, options.Runtime{ControllerAddr: "127.0.0.1:0", Secret: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Parse(buf); err != nil {
			t.Fatalf("%s: mihomo rejected the config: %v\n%s", name, err, buf)
		}
		if len(p.Unsupported) != 1 {
			t.Errorf("%s: unsupported %v", name, p.Unsupported)
		}
	}
}

// grpcsvc relies on mihomo naming a refused proxy as "proxy N: ..." with N its index in proxies.
func TestRefusedProxyErrorNamesIndex(t *testing.T) {
	m := &Mihomo{}
	p := &profile.Profile{Kind: profile.KindURIList, Proxies: []map[string]any{
		{"name": "ok", "type": "trojan", "server": "127.0.0.1", "port": 443, "password": "pw"},
		{"name": "bad", "type": "ss", "server": "127.0.0.1", "port": 1, "cipher": "no-such-cipher", "password": "pw"},
	}}
	buf, err := options.Build(p, options.Defaults(), options.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Parse(buf)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !regexp.MustCompile(`^proxy 1: `).MatchString(err.Error()) {
		t.Fatalf("error format changed: %v", err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func listening(port int) bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Full path through the service and the real engine: start opens the mixed port and the local
// API (with its secret), stop closes both. No outside network is used.
func TestServiceStartStopRealEngine(t *testing.T) {
	m := &Mihomo{}
	svc := grpcsvc.New(m)
	dir := t.TempDir()
	svc.Prepare(dir)
	mixed, api := freePort(t), freePort(t)
	js := `{"mixed-port":` + strconv.Itoa(mixed) + `,"enable-clash-api":true,"clash-api-port":` + strconv.Itoa(api) + `,"web-secret":"sec","log-level":"warn"}`
	if _, err := svc.ChangeHiddifySettings(t.Context(), &hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: js}); err != nil {
		t.Fatal(err)
	}
	res := svc.StartCore(&hcore.StartRequest{ConfigContent: uriSub, ConfigName: "t"})
	if res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("start: %v", res)
	}
	waitUntil(t, "mixed port", func() bool { return listening(mixed) })
	waitUntil(t, "local API", func() bool { return listening(api) })

	get := func(secret string) int {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(api)+"/version", nil)
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			return -1
		}
		r.Body.Close()
		return r.StatusCode
	}
	if code := get(""); code != http.StatusUnauthorized {
		t.Errorf("API without secret: %d", code)
	}
	if code := get("sec"); code != http.StatusOK {
		t.Errorf("API with secret: %d", code)
	}
	if cur := m.Current(options.GroupSelect); !strings.HasPrefix(cur, options.GroupAuto) {
		t.Errorf("current %q", cur)
	}
	info, _ := svc.GetSystemInfo(t.Context(), nil)
	if !info.TrafficAvailable || info.CurrentProfile != "t" {
		t.Errorf("info %+v", info)
	}

	if res := svc.StopCore(); res.CoreState != hcore.CoreStates_STOPPED {
		t.Fatalf("stop: %v", res)
	}
	waitUntil(t, "mixed port closed", func() bool { return !listening(mixed) })
	waitUntil(t, "local API closed", func() bool { return !listening(api) })

	// and it starts again after a stop
	if res := svc.StartCore(&hcore.StartRequest{}); res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("restart: %v", res)
	}
	waitUntil(t, "mixed port again", func() bool { return listening(mixed) })
	svc.StopCore()
	waitUntil(t, "mixed port closed again", func() bool { return !listening(mixed) })
}

// Groups, selection, delay tests and hot reload against the real engine, offline: a "direct"
// node reaches a local HTTP server, a node at a closed local port fails.
func TestGroupsSelectTestReloadRealEngine(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer web.Close()
	m := &Mihomo{}
	svc := grpcsvc.New(m)
	svc.Prepare(t.TempDir())
	mixed := freePort(t)
	js := `{"mixed-port":` + strconv.Itoa(mixed) + `,"connection-test-url":"` + web.URL + `/204","muse-test-timeout-ms":2000}`
	if _, err := svc.ChangeHiddifySettings(t.Context(), &hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: js}); err != nil {
		t.Fatal(err)
	}
	sub := "proxies:\n  - {name: D, type: direct}\n  - {name: X, type: trojan, server: 127.0.0.1, port: 1, password: pw}\n"
	if res := svc.StartCore(&hcore.StartRequest{ConfigContent: sub}); res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("start %v", res)
	}
	defer svc.StopCore()
	list := svc.GroupList(false)
	if len(list.Items) != 2 || list.Items[0].Tag != options.GroupSelect || list.Items[1].Tag != options.GroupAuto {
		t.Fatalf("groups %v", list.Items)
	}
	var names []string
	for _, it := range list.Items[0].Items {
		names = append(names, it.Tag+"/"+it.Type)
	}
	if strings.Join(names, ",") != "lowest/URLTest,D/Direct,X/Trojan" {
		t.Errorf("select items %v", names)
	}
	if list.Items[1].Type != "urltest" || !list.Items[0].Selectable {
		t.Errorf("types %v %v", list.Items[1].Type, list.Items[0].Selectable)
	}

	if r, err := svc.SelectOutbound(t.Context(), &hcore.SelectOutboundRequest{GroupTag: "select", OutboundTag: "X"}); err != nil || r.Code != 0 {
		t.Fatalf("select %v %v", r, err)
	}
	if _, err := svc.SelectOutbound(t.Context(), &hcore.SelectOutboundRequest{GroupTag: "lowest", OutboundTag: "X"}); err == nil {
		t.Error("url-test group must not be selectable")
	}

	if d, err := m.TestDelay(t.Context(), "D", web.URL+"/204", 2*time.Second); err != nil || d == 0 {
		t.Fatalf("direct delay %d %v", d, err)
	}
	if _, err := svc.UrlTest(t.Context(), &hcore.UrlTestRequest{Tag: "X"}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "X tested", func() bool { return m.Nodes()["X"].Delay != 0 && !svc.Testing() })
	nodes := m.Nodes()
	if nodes["X"].Delay != grpcsvc.DelayFailed || nodes["D"].Delay == 0 || nodes["D"].Delay == grpcsvc.DelayFailed {
		t.Errorf("delays D=%d X=%d", nodes["D"].Delay, nodes["X"].Delay)
	}

	// hot reload: a new node, the selection and the mixed port stay
	sub2 := sub + "  - {name: Y, type: direct}\n"
	if r := svc.HotReloadCore(&hcore.StartRequest{ConfigContent: sub2}); r.CoreState != hcore.CoreStates_STARTED || r.MessageType != hcore.MessageType_EMPTY {
		t.Fatalf("reload %v", r)
	}
	if now := m.Nodes()["select"].Now; now != "X" {
		t.Errorf("selection after reload %q", now)
	}
	if _, ok := m.Nodes()["Y"]; !ok {
		t.Error("new node missing")
	}
	if !listening(mixed) {
		t.Error("mixed port closed by hot reload")
	}
}
