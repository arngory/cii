//go:build !windows

package netx

import "syscall"

var (
	errnoRefused     = []syscall.Errno{syscall.ECONNREFUSED}
	errnoReset       = []syscall.Errno{syscall.ECONNRESET}
	errnoUnreachable = []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH}
	errnoTimedOut    = []syscall.Errno{syscall.ETIMEDOUT}
)
