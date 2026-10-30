// Package sysproxy points the system's proxy settings at the core's mixed port while the core
// runs in 系统代理 mode (Windows; elsewhere the app or the OS service does it, so it is a no-op).
// Same behaviour as the main core: set on start, blanked on stop; the app's own guard puts the
// user's previous settings back afterwards.
package sysproxy

import "strconv"

// Setter changes the system proxy (a fake in tests).
type Setter interface {
	Set(port uint16) error
	Clear() error
}

// Bypass: local names, loopback and private ranges never go through the proxy.
const Bypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// Server is the proxy address written for port.
func Server(port uint16) string { return "http://127.0.0.1:" + strconv.Itoa(int(port)) }

// Default is the platform's setter.
var Default Setter = platform{}
