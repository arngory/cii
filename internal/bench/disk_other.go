//go:build !linux && !windows

package bench

import "os"

func openDirect(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, false, err
	}
	return f, disableCache(f), nil
}
