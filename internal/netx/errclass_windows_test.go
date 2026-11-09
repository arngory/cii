package netx

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestWinsockCodes(t *testing.T) {
	wrap := func(code syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", code)}
	}
	cases := []struct {
		code syscall.Errno
		is   func(error) bool
	}{
		{10061, IsRefused},
		{10054, IsReset},
		{10053, IsReset},
		{10051, IsUnreachable},
		{10065, IsUnreachable},
		{10060, IsTimeout},
	}
	for _, c := range cases {
		if !c.is(wrap(c.code)) {
			t.Errorf("winsock error %d not classified", c.code)
		}
	}
}
