package engine

import (
	"context"
	"errors"
	"time"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/yywgov/muse-core/mihomo/grpcsvc"
)

// mihomo adapter type -> the display name the main core reports for the same protocol
var displayType = map[string]string{
	"Vless": "VLESS", "Vmess": "VMess", "Trojan": "Trojan", "Shadowsocks": "Shadowsocks",
	"ShadowsocksR": "ShadowsocksR", "Hysteria": "Hysteria", "Hysteria2": "Hysteria2", "Tuic": "TUIC",
	"WireGuard": "WireGuard", "Socks5": "SOCKS", "Http": "HTTP", "Ssh": "SSH", "AnyTLS": "AnyTLS",
	"Snell": "Snell", "Mieru": "Mieru", "Direct": "Direct", "Reject": "Block", "RejectDrop": "Block",
	"Selector": "Selector", "URLTest": "URLTest", "Fallback": "Fallback", "LoadBalance": "LoadBalance", "Relay": "Relay",
}

// mihomo group type -> the group type string the app knows (the main core's for selector/urltest)
var groupType = map[string]string{
	"Selector": "selector", "URLTest": "urltest", "Fallback": "fallback", "LoadBalance": "load-balance", "Relay": "relay",
}

type groupAdapter interface {
	Now() string
	GetProxies(touch bool) []C.Proxy
}

func nodeInfo(p C.Proxy) grpcsvc.NodeInfo {
	t := p.Type().String()
	n := grpcsvc.NodeInfo{Name: p.Name(), Type: t}
	if d, ok := displayType[t]; ok {
		n.Type = d
	}
	if g, ok := p.Adapter().(groupAdapter); ok {
		n.Group = true
		n.GroupType = groupType[t]
		n.Now = g.Now()
		for _, m := range g.GetProxies(false) {
			n.Members = append(n.Members, m.Name())
		}
		if h, ok := p.Adapter().(interface{ Hidden() bool }); ok {
			n.Hidden = h.Hidden()
		}
	}
	if hist := p.DelayHistory(); len(hist) > 0 {
		last := hist[len(hist)-1]
		n.Tested = last.Time
		n.Delay = last.Delay
		if last.Delay == 0 {
			n.Delay = grpcsvc.DelayFailed
		}
	}
	return n
}

// Nodes returns every proxy and group of the running config, including provider members.
func (m *Mihomo) Nodes() map[string]grpcsvc.NodeInfo {
	proxies := tunnel.Proxies()
	out := make(map[string]grpcsvc.NodeInfo, len(proxies))
	for name, p := range proxies {
		out[name] = nodeInfo(p)
		if g, ok := p.Adapter().(groupAdapter); ok {
			for _, member := range g.GetProxies(false) {
				if _, seen := out[member.Name()]; !seen {
					if _, inMap := proxies[member.Name()]; !inMap {
						out[member.Name()] = nodeInfo(member)
					}
				}
			}
		}
	}
	return out
}

func (m *Mihomo) find(name string) C.Proxy {
	proxies := tunnel.Proxies()
	if p, ok := proxies[name]; ok {
		return p
	}
	for _, p := range proxies {
		if g, ok := p.Adapter().(groupAdapter); ok {
			for _, member := range g.GetProxies(false) {
				if member.Name() == name {
					return member
				}
			}
		}
	}
	return nil
}

// ErrNotSelector: only select groups can be switched by hand (as on the main core).
var ErrNotSelector = errors.New("outbound is not a selector")

// Select switches a select group to one of its members.
func (m *Mihomo) Select(group, name string) error {
	p, ok := tunnel.Proxies()[group]
	if !ok {
		return errors.New("selector not found: " + group)
	}
	if p.Type() != C.Selector {
		return ErrNotSelector
	}
	s, ok := p.Adapter().(interface{ Set(string) error })
	if !ok {
		return ErrNotSelector
	}
	return s.Set(name)
}

// TestDelay measures one node through itself (mihomo records the result in the node's history).
func (m *Mihomo) TestDelay(ctx context.Context, name, url string, timeout time.Duration) (uint16, error) {
	p := m.find(name)
	if p == nil {
		return 0, errors.New("outbound not found: " + name)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return p.URLTest(ctx, url, nil)
}

// Reload applies a parsed config to the running core without restarting listeners that did not
// change; the local API server is recreated only when its address or secret changed.
func (m *Mihomo) Reload(parsed any) {
	cfg := parsed.(*config.Config)
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctl := cfg.Controller.ExternalController + "\x00" + cfg.Controller.Secret; ctl != m.controller || !m.running {
		hub.ApplyConfig(cfg) // recreates the local API server, then applies like below with force
		m.controller = ctl
	} else {
		executor.ApplyConfig(cfg, false)
	}
	m.running = true
}
