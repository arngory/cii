//go:build darwin

package bench

import (
	"os"

	"golang.org/x/sys/unix"
)

func disableCache(f *os.File) bool {
	_, err := unix.FcntlInt(f.Fd(), unix.F_NOCACHE, 1)
	return err == nil
}
