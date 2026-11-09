package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func errnoErrors(codes []syscall.Errno) []error {
	out := make([]error, len(codes))
	for i, c := range codes {
		out[i] = c
	}
	return out
}

func TestErrorClasses(t *testing.T) {
	wrap := func(code error) error {
		return fmt.Errorf("probe: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", code)})
	}
	classes := []struct {
		name  string
		is    func(error) bool
		codes []error
	}{
		{"refused", IsRefused, errnoErrors(errnoRefused)},
		{"reset", IsReset, errnoErrors(errnoReset)},
		{"unreachable", IsUnreachable, errnoErrors(errnoUnreachable)},
		{"timeout", IsTimeout, append(errnoErrors(errnoTimedOut), context.DeadlineExceeded, os.ErrDeadlineExceeded)},
	}
	for i, c := range classes {
		if len(c.codes) == 0 {
			t.Fatalf("%s: no codes", c.name)
		}
		for _, code := range c.codes {
			for j, other := range classes {
				if got := other.is(wrap(code)); got != (i == j) {
					t.Errorf("%s(%v) = %v", other.name, code, got)
				}
			}
		}
		if c.is(nil) || c.is(errors.New("connection refused, reset, unreachable, timeout")) {
			t.Errorf("%s matches a non-errno error", c.name)
		}
	}
}
