//go:build windows

package bench

import (
	"os"

	"golang.org/x/sys/windows"
)

func openDirect(path string) (*os.File, bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_NO_BUFFERING|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err == nil {
		return os.NewFile(uintptr(h), path), true, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	return f, false, err
}

func freeSpace(dir string) (uint64, error) {
	var free, total, avail uint64
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &avail); err != nil {
		return 0, err
	}
	return free, nil
}
