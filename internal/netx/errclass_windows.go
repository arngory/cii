package netx

import (
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	errnoRefused     = []syscall.Errno{windows.WSAECONNREFUSED, syscall.ECONNREFUSED}
	errnoReset       = []syscall.Errno{windows.WSAECONNRESET, windows.WSAECONNABORTED, syscall.ECONNRESET}
	errnoUnreachable = []syscall.Errno{windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTUNREACH}
	errnoTimedOut    = []syscall.Errno{windows.WSAETIMEDOUT, syscall.ETIMEDOUT}
)
