package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

const appDir = "cii"

func ConfigDir() string {
	if d := os.Getenv("CII_CONFIG_DIR"); d != "" {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, appDir)
	}
	return filepath.Join(".", "."+appDir)
}

func DataDir() string {
	if d := os.Getenv("CII_DATA_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, appDir)
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Application Support", appDir)
		}
	default:
		if d := os.Getenv("XDG_DATA_HOME"); d != "" {
			return filepath.Join(d, appDir)
		}
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, ".local", "share", appDir)
		}
	}
	return filepath.Join(".", "."+appDir, "data")
}

func LogDir() string {
	if d := os.Getenv("CII_LOG_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, appDir, "logs")
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Logs", appDir)
		}
	default:
		if d := os.Getenv("XDG_STATE_HOME"); d != "" {
			return filepath.Join(d, appDir, "logs")
		}
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, ".local", "state", appDir, "logs")
		}
	}
	return filepath.Join(".", "."+appDir, "logs")
}
