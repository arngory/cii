package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/paths"
)

type Keys struct {
	IPinfoToken       string `yaml:"ipinfo_token"`
	MaxMindAccountID  string `yaml:"maxmind_account_id"`
	MaxMindLicenseKey string `yaml:"maxmind_license_key"`
}

type Config struct {
	IPEcho []ipdetect.Provider `yaml:"ip_echo"`
	Keys   Keys                `yaml:"keys"`
	Data   struct {
		Sources []string `yaml:"sources"`
	} `yaml:"data"`
}

func DefaultPath() string { return filepath.Join(paths.ConfigDir(), "config.yaml") }

func Load(path string) (*Config, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultPath()
	}
	c := &Config{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist) && !explicit:
	default:
		return nil, fmt.Errorf("config: %w", err)
	}
	envOverride(&c.Keys.IPinfoToken, "CII_IPINFO_TOKEN")
	envOverride(&c.Keys.MaxMindAccountID, "CII_MAXMIND_ACCOUNT_ID")
	envOverride(&c.Keys.MaxMindLicenseKey, "CII_MAXMIND_LICENSE_KEY")
	return c, nil
}

func envOverride(dst *string, name string) {
	if v := os.Getenv(name); v != "" {
		*dst = v
	}
}
