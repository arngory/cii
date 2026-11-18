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
	IPRegistryKey     string `yaml:"ipregistry_key"`
	GeoapifyKey       string `yaml:"geoapify_key"`
	IP2LocationKey    string `yaml:"ip2location_key"`
	IPAPIisKey        string `yaml:"ipapi_is_key"`
	ProxyCheckKey     string `yaml:"proxycheck_key"`
	AbuseIPDBKey      string `yaml:"abuseipdb_key"`
	IPQSKey           string `yaml:"ipqs_key"`
	IPDataKey         string `yaml:"ipdata_key"`
	GeminiAPIKey      string `yaml:"gemini_api_key"`
}

type Codes []int

func (c *Codes) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var one int
		if err := n.Decode(&one); err != nil {
			return err
		}
		*c = Codes{one}
		return nil
	}
	var many []int
	if err := n.Decode(&many); err != nil {
		return err
	}
	*c = many
	return nil
}

type ServiceCheck struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	Expect   Codes  `yaml:"expect"`
	Contains string `yaml:"contains"`
	Blocked  string `yaml:"blocked"`
	Group    string `yaml:"group"`
}

type Config struct {
	IPEcho []ipdetect.Provider `yaml:"ip_echo"`
	Keys   Keys                `yaml:"keys"`
	Data   struct {
		Sources []string `yaml:"sources"`
	} `yaml:"data"`
	Route struct {
		Targets []string `yaml:"targets"`
	} `yaml:"route"`
	Services []ServiceCheck `yaml:"services"`
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
	envOverride(&c.Keys.IPRegistryKey, "CII_IPREGISTRY_KEY")
	envOverride(&c.Keys.GeoapifyKey, "CII_GEOAPIFY_KEY")
	envOverride(&c.Keys.IP2LocationKey, "CII_IP2LOCATION_KEY")
	envOverride(&c.Keys.IPAPIisKey, "CII_IPAPI_IS_KEY")
	envOverride(&c.Keys.ProxyCheckKey, "CII_PROXYCHECK_KEY")
	envOverride(&c.Keys.AbuseIPDBKey, "CII_ABUSEIPDB_KEY")
	envOverride(&c.Keys.IPQSKey, "CII_IPQS_KEY")
	envOverride(&c.Keys.GeminiAPIKey, "CII_GEMINI_API_KEY")
	envOverride(&c.Keys.IPDataKey, "CII_IPDATA_KEY")
	return c, nil
}

func envOverride(dst *string, name string) {
	if v := os.Getenv(name); v != "" {
		*dst = v
	}
}
