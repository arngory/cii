//go:build !linux && !windows

package bench

import "os"

func openDirect(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, exclusiveFlags, 0o600)
	if err != nil {
		return nil, false, err
	}
	return f, disableCache(f), nil
}
