// Package engine runs mihomo in this process: parse and apply a config, stop it, read traffic
// counters and logs. It is the only package that touches mihomo's global state; grpcsvc talks to
// it through the grpcsvc.Engine interface so the service logic is tested without a network.
package engine

import (
	"runtime"
	"sync"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	mlog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/yywgov/muse-core/mihomo/grpcsvc"
)

// Mihomo is the real engine. The zero value is ready; only one may be used per process.
type Mihomo struct {
	mu         sync.Mutex
	running    bool
	controller string // address + secret of the local API last applied
}

// stopped config: no listener, no TUN, nothing to route
const idleConfig = "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: direct\nlog-level: warning\nproxies: []\nproxy-groups: []\nrules: []\ndns:\n  enable: false\ntun:\n  enable: false\n"

func (m *Mihomo) SetHomeDir(dir string) {
	if dir != "" {
		C.SetHomeDir(dir)
	}
}

// Parse checks a config without applying it.
func (m *Mihomo) Parse(buf []byte) (any, error) {
	return executor.ParseWithBytes(buf)
}

// Apply runs a parsed config (listeners, DNS, TUN, local API), replacing the running one.
func (m *Mihomo) Apply(parsed any) {
	cfg := parsed.(*config.Config)
	m.mu.Lock()
	defer m.mu.Unlock()
	tunnel.OnRunning()
	hub.ApplyConfig(cfg)
	m.running = true
	m.controller = cfg.Controller.ExternalController + "\x00" + cfg.Controller.Secret
}

// Stop closes listeners, TUN, the local API and every open connection.
func (m *Mihomo) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	m.running = false
	m.controller = ""
	route.ReCreateServer(&route.Config{})
	if cfg, err := executor.ParseWithBytes([]byte(idleConfig)); err == nil {
		executor.ApplyConfig(cfg, true)
	}
	executor.Shutdown()
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
	tunnel.OnSuspend()
	runtime.GC()
}

// Traffic returns speeds (bytes/s over the last second), totals and open connections.
func (m *Mihomo) Traffic() (up, down, upTotal, downTotal int64, conns int32) {
	up, down = statistic.DefaultManager.Now()
	upTotal, downTotal = statistic.DefaultManager.Total()
	statistic.DefaultManager.Range(func(statistic.Tracker) bool {
		conns++
		return true
	})
	return
}

// Current is the node the main selector uses, followed through nested groups ("select→lowest→A").
func (m *Mihomo) Current(group string) string {
	proxies := tunnel.Proxies()
	out := ""
	name := group
	for i := 0; i < 4; i++ {
		p, ok := proxies[name]
		if !ok {
			break
		}
		g, ok := p.Adapter().(interface{ Now() string })
		if !ok {
			break
		}
		now := g.Now()
		if now == "" {
			break
		}
		if out == "" {
			out = now
		} else {
			out += "→" + now
		}
		name = now
	}
	return out
}

// SubscribeLogs streams mihomo's log until cancel is called.
func (m *Mihomo) SubscribeLogs() (<-chan grpcsvc.LogEvent, func()) {
	sub := mlog.Subscribe()
	out := make(chan grpcsvc.LogEvent, 64)
	done := make(chan struct{})
	go func() {
		defer close(out)
		for {
			select {
			case <-done:
				return
			case ev, ok := <-sub:
				if !ok {
					return
				}
				select {
				case out <- grpcsvc.LogEvent{Level: ev.LogLevel.String(), Payload: ev.Payload}:
				default: // slow reader: drop rather than block mihomo's logger
				}
			}
		}
	}()
	var once sync.Once
	return out, func() {
		once.Do(func() {
			close(done)
			mlog.UnSubscribe(sub)
		})
	}
}

// Version is mihomo's version string (set at link time).
func (m *Mihomo) Version() string { return C.Version }
