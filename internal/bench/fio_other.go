//go:build !linux

package bench

func fioEngine() string { return "psync" }
