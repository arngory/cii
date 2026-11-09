//go:build !linux && !darwin && !windows

package bench

import "os"

func disableCache(*os.File) bool { return false }
