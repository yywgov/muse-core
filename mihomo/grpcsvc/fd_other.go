//go:build !unix

package grpcsvc

import "errors"

func dupFD(int) (int, error) { return 0, errors.New("a TUN file descriptor is only used on Android") }
func closeFD(int)            {}
