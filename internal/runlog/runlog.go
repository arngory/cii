package runlog

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
		os.Remove(path)
		return "", err
	}
	prune(dir)
	return path, nil
}

const JSONMarker = "\n--- JSON ---\n"

var logName = regexp.MustCompile(`^\d{8}-\d{6}-\d{2}\.log$`)

func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var logs []string
	for _, e := range entries {
		if !e.IsDir() && logName.MatchString(e.Name()) {
			logs = append(logs, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(logs)
	return logs, nil
}

func prune(dir string) {
	logs, err := List(dir)
	if err != nil {
		return
	}
	for len(logs) > Keep {
		os.Remove(logs[0])
		logs = logs[1:]
	}
}

func ReportJSON(data []byte) []byte {
	if _, after, ok := bytes.Cut(data, []byte(JSONMarker)); ok {
		return after
	}
	return data
}
