package grpcsvc

import (
	"context"
	"os"
	"testing"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
)

type fakeProxy struct {
	calls []string
}

func (p *fakeProxy) Set(port uint16) error {
	p.calls = append(p.calls, "set:"+itoa(int(port)))
	return nil
}
func (p *fakeProxy) Clear() error { p.calls = append(p.calls, "clear"); return nil }

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

// Android: the VPN service's TUN goes into the config as a duplicate per start (the engine closes
// its copy on stop; the service keeps its own for the next start); routes stay with the service.
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

	dev, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	orig := int(dev.Fd())
	s.SetTunFD(orig)
	s.StartCore(&hcore.StartRequest{ConfigPath: path})
	tun = f.lastConfig(t)["tun"].(map[string]any)
	first, _ := tun["file-descriptor"].(int)
	if first <= 0 || first == orig || tun["auto-route"] != false || tun["auto-detect-interface"] != false {
		t.Fatalf("fd config %v (service fd %d)", tun, orig)
	}
	if _, ok := tun["strict-route"]; ok {
		t.Fatalf("strict-route belongs to the VPN service: %v", tun)
	}
	// a hot reload keeps the same TUN
	s.HotReloadCore(&hcore.StartRequest{ConfigPath: path})
	if got := f.lastConfig(t)["tun"].(map[string]any)["file-descriptor"]; got != first {
		t.Fatalf("hot reload changed the TUN fd: %v → %v", first, got)
	}
	s.StopCore()
	closeFD(first) // the real engine closes it with its TUN

	// proxy mode inside the VPN service: no TUN, nothing duplicated
	settings(t, s, `{"enable-tun":false}`)
	s.StartCore(&hcore.StartRequest{ConfigPath: path})
	if _, ok := f.lastConfig(t)["tun"]; ok {
		t.Fatal("tun without enable-tun")
	}
	s.StopCore()

	// a descriptor that cannot be duplicated: the start fails cleanly
	settings(t, s, `{"enable-tun":true}`)
	s.SetTunFD(1 << 20)
	res := s.StartCore(&hcore.StartRequest{ConfigPath: path})
	if res.CoreState != hcore.CoreStates_STOPPED || res.MessageType != hcore.MessageType_START_SERVICE {
		t.Fatalf("bad fd start %v", res)
	}
}
