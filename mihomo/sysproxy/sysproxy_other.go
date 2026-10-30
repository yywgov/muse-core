//go:build !windows

package sysproxy

type platform struct{}

func (platform) Set(uint16) error { return nil }
func (platform) Clear() error     { return nil }
