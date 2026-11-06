package grpcsvc

// 穿云 1.12.0 - why a delay test failed, the same four words as the main core: refused, dns,
// handshake, timeout. Anything unclear is timeout. Reporting only; the tests do not change.

import (
	"errors"
	"net"
	"strings"
)

func FailReason(err error) string {
	if err == nil {
		return "timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return "dns"
	}
	s := strings.ToLower(err.Error())
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(s, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("connection refused", "actively refused"):
		return "refused"
	case has("no such host", "nxdomain", "server misbehaving", "no address", "lookup "):
		return "dns"
	case has("timeout", "timed out", "deadline exceeded", "context canceled"):
		return "timeout"
	case has("tls", "handshake", "reality", "x509", "certificate", "connection reset", "reset by peer",
		"forcibly closed", "unexpected eof", "eof", "bad response", "malformed", "authentication", "invalid user"):
		return "handshake"
	}
	return "timeout"
}
