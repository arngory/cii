//go:build linux

package bench

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openDirect(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, exclusiveFlags|unix.O_DIRECT, 0o600)
	if err == nil {
		return f, true, nil
	}
	if errors.Is(err, os.ErrExist) {
		return nil, false, err
	}
	os.Remove(path)
	f, err = os.OpenFile(path, exclusiveFlags, 0o600)
	return f, false, err
}
