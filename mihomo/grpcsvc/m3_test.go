package grpcsvc

import (
	"context"
	"testing"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
)

type fakeProxy struct {
	calls []string
}

func (p *fakeProxy) Set(port uint16) error { p.calls = append(p.calls, "set:"+itoa(int(port))); return nil }
func (p *fakeProxy) Clear() error          { p.calls = append(p.calls, "clear"); return nil }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func settings(t *testing.T, s *Service, js string) {
	t.Helper()
	res, err := s.ChangeHiddifySettings(context.Background(), &hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: js})
	if err != nil || res.MessageType != hcore.MessageType_EMPTY {
		t.Fatalf("settings %v %v", res, err)
	}
}

// 系统代理 mode: set on start, blanked on stop; TUN mode and the default never touch it.
func TestSystemProxyFollowsStartStop(t *testing.T) {
	f := newFake()
	s := New(f)
	px := &fakeProxy{}
	s.SysProxy = px
	dir := t.TempDir()
	s.Prepare(dir)
	path := writeProfile(t, dir, links)

	// default settings: no system proxy
	s.StartCore(&hcore.StartRequest{ConfigPath: path})
	s.StopCore()
	if len(px.calls) != 0 {
		t.Fatalf("default touched the system proxy: %v", px.calls)
	}

	settings(t, s, `{"mixed-port":12334,"set-system-proxy":true,"enable-tun":false}`)
	if res := s.StartCore(&hcore.StartRequest{ConfigPath: path}); res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("start %v", res)
	}
	// hot reload with the same port: no second write
	s.HotReloadCore(&hcore.StartRequest{ConfigPath: path})
	// port changed: written again
	settings(t, s, `{"mixed-port":12335,"set-system-proxy":true,"enable-tun":false}`)
	s.HotReloadCore(&hcore.StartRequest{ConfigPath: path})
	// switched off while running: blanked
	settings(t, s, `{"mixed-port":12335,"set-system-proxy":false,"enable-tun":false}`)
	s.HotReloadCore(&hcore.StartRequest{ConfigPath: path})
	s.StopCore()
	want := []string{"set:12334", "set:12335", "clear"}
	if len(px.calls) != len(want) {
		t.Fatalf("calls %v want %v", px.calls, want)
	}
	for i := range want {
		if px.calls[i] != want[i] {
			t.Fatalf("calls %v want %v", px.calls, want)
		}
	}

	// set → stop blanks it
	px.calls = nil
	settings(t, s, `{"mixed-port":12334,"set-system-proxy":true}`)
	s.StartCore(&hcore.StartRequest{ConfigPath: path})
	s.StopCore()
	if len(px.calls) != 2 || px.calls[0] != "set:12334" || px.calls[1] != "clear" {
		t.Fatalf("start/stop calls %v", px.calls)
	}

	// TUN: never the system proxy, even if both are on
	px.calls = nil
	settings(t, s, `{"mixed-port":12334,"set-system-proxy":true,"enable-tun":true}`)
	s.StartCore(&hcore.StartRequest{ConfigPath: path})
	s.StopCore()
	if len(px.calls) != 0 {
		t.Fatalf("TUN touched the system proxy: %v", px.calls)
	}
}

// Android: the VPN service's TUN fd goes into the config; routes stay with the service.
func TestTunFileDescriptorFromService(t *testing.T) {
	f := newFake()
	s := New(f)
	s.SysProxy = &fakeProxy{}
	dir := t.TempDir()
	s.Prepare(dir)
	path := writeProfile(t, dir, links)
	settings(t, s, `{"enable-tun":true}`)

	s.StartCore(&hcore.StartRequest{ConfigPath: path})
	tun := f.lastConfig(t)["tun"].(map[string]any)
	if _, ok := tun["file-descriptor"]; ok || tun["auto-route"] != true {
		t.Fatalf("without fd the core makes its own TUN: %v", tun)
	}
	s.StopCore()

	s.SetTunFD(42)
	s.StartCore(&hcore.StartRequest{ConfigPath: path})
	tun = f.lastConfig(t)["tun"].(map[string]any)
	if tun["file-descriptor"] != 42 || tun["auto-route"] != false || tun["auto-detect-interface"] != false {
		t.Fatalf("fd config %v", tun)
	}
	if _, ok := tun["strict-route"]; ok {
		t.Fatalf("strict-route belongs to the VPN service: %v", tun)
	}
	s.StopCore()
}
