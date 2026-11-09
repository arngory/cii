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

func freeSpace(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
