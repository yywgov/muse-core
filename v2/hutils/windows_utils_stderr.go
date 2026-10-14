//go:build windows

package hutils

import (
	"os"
	"path/filepath"
	"runtime/debug"

	"golang.org/x/sys/windows"
)

// redirectStderrWindows: 穿云 1.2.1 — on Windows the core runs inside Chuanyun.exe, so a Go
// panic or fatal error used to vanish with the process (RedirectStderr was "not supported").
// The previous run's file is kept as *.old.log so a crash survives the relaunch that follows.
func redirectStderrWindows(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		ext := filepath.Ext(path)
		old := path[:len(path)-len(ext)] + ".old" + ext
		_ = os.Remove(old)
		_ = os.Rename(path, old)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	// Go runtime crash output (unrecovered panics, fatal errors) goes here as well
	if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
		f.Close()
		return err
	}
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	os.Stderr = f
	return nil
}
