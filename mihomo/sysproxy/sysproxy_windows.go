//go:build windows

package sysproxy

import "github.com/metacubex/sing/common/wininet"

type platform struct{}

func (platform) Set(port uint16) error { return wininet.SetSystemProxy(Server(port), Bypass) }
func (platform) Clear() error          { return wininet.ClearSystemProxy() }
