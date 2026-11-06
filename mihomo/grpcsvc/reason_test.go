package grpcsvc

import (
	"errors"
	"net"
	"testing"
)

func TestMuseFailReasonCompat(t *testing.T) {
	cases := map[string]error{
		"refused":   errors.New("dial tcp 1.2.3.4:443: connect: connection refused"),
		"dns":       &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true},
		"handshake": errors.New("tls: handshake failure"),
		"timeout":   errors.New("i/o timeout"),
	}
	for want, err := range cases {
		if got := FailReason(err); got != want {
			t.Fatalf("%v: got %s want %s", err, got, want)
		}
	}
	if FailReason(errors.New("odd")) != "timeout" || FailReason(nil) != "timeout" {
		t.Fatal("unknown must be timeout")
	}
}
