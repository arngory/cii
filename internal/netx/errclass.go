package netx

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

const ReasonUnreachable = "network unreachable"

func Short(err error) string {
	switch {
	case IsTimeout(err):
		return "timeout"
	case IsRefused(err):
		return "connection refused"
	case IsReset(err):
		return "connection reset"
	case IsUnreachable(err):
		return ReasonUnreachable
	}
	return ""
}

func IsRefused(err error) bool     { return isErrno(err, errnoRefused) }
func IsReset(err error) bool       { return isErrno(err, errnoReset) }
func IsUnreachable(err error) bool { return isErrno(err, errnoUnreachable) }

func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || isErrno(err, errnoTimedOut) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isErrno(err error, codes []syscall.Errno) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	for _, c := range codes {
		if errno == c {
			return true
		}
	}
	return false
}
