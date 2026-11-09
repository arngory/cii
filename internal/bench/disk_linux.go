//go:build linux

package bench

import (
	"os"

	"golang.org/x/sys/unix"
)

func openDirect(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC|unix.O_DIRECT, 0o600)
	if err == nil {
		return f, true, nil
	}
	f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	return f, false, err
}

func freeSpace(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
