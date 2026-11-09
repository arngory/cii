//go:build !linux && !darwin && !windows

package bench

import (
	"os"

	"golang.org/x/sys/unix"
)

func disableCache(*os.File) bool { return false }

func freeSpace(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
