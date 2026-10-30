//go:build unix

package grpcsvc

import "syscall"

func dupFD(fd int) (int, error) { return syscall.Dup(fd) }
func closeFD(fd int)            { _ = syscall.Close(fd) }
