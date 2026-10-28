//go:build windows

package engine

import (
	tun "github.com/metacubex/sing-tun"
	"github.com/yywgov/muse-core/mihomo/grpcsvc"
)

// The TUN adapter's description (Windows shows it next to the name) is the app's, not the engine's
// default. Runs after the engine's own init, which sets the default.
func init() { tun.TunnelType = grpcsvc.TunAdapterName }
