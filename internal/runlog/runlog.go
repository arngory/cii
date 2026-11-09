package runlog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const Keep = 20

func Write(dir string, now time.Time, sections ...[]byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	stamp := now.UTC().Format("20060102-150405")
	var f *os.File
	var path string
	for i := 0; ; i++ {
		path = filepath.Join(dir, fmt.Sprintf("%s-%02d.log", stamp, i))
		var err error
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || i >= 99 {
			return "", err
		}
	}
	var err error
	for _, s := range sections {
		if _, err = f.Write(s); err != nil {
			break
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	prune(dir)
	return path, nil
}

func prune(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var logs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			logs = append(logs, e.Name())
		}
	}
	sort.Strings(logs)
	for len(logs) > Keep {
		os.Remove(filepath.Join(dir, logs[0]))
		logs = logs[1:]
	}
}
