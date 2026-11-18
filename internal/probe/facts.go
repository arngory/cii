package probe

import (
	"math"
	"strings"
)

type Flag string

const (
	Proxy   Flag = "proxy"
	VPN     Flag = "vpn"
	Tor     Flag = "tor"
	Hosting Flag = "hosting"
	Abuser  Flag = "abuser"
	Bot     Flag = "bot"
)

var Flags = []Flag{Proxy, VPN, Tor, Hosting, Abuser, Bot}

type Facts struct {
	Usage   string        `json:"usage,omitempty"`
	Company string        `json:"company,omitempty"`
	Score   *int          `json:"score,omitempty"`
	Level   *int          `json:"level,omitempty"`
	Flags   map[Flag]bool `json:"flags,omitempty"`
}

func (f *Facts) Set(flag Flag, on bool) {
	if f.Flags == nil {
		f.Flags = map[Flag]bool{}
	}
	f.Flags[flag] = f.Flags[flag] || on
}

func (f *Facts) SetIf(flag Flag, v *bool) {
	if v != nil {
		f.Set(flag, *v)
	}
}

func (f *Facts) SetScore(v float64) {
	s := int(math.Round(min(max(v, 0), 100)))
	f.Score = &s
}

func (f *Facts) SetLevel(level int) {
	l := min(max(level, 0), MaxLevel)
	f.Level = &l
}

const MaxLevel = 4

func LevelByThresholds(score float64, upper ...float64) int {
	for i, u := range upper {
		if score < u {
			return i
		}
	}
	return len(upper)
}

var levelNames = map[string]int{"very low": 0, "low": 1, "medium": 2, "elevated": 2, "high": 3, "very high": 4}

func (f *Facts) SetLevelName(name string) {
	if l, ok := levelNames[strings.ToLower(strings.TrimSpace(name))]; ok {
		f.SetLevel(l)
	}
}

func (f *Facts) SetUsage(raw string) {
	if u := NormalizeUsage(raw); u != "" {
		f.Usage = u
	}
}

func (f *Facts) SetCompany(raw string) {
	if u := NormalizeUsage(raw); u != "" {
		f.Company = u
	}
}

func (f *Facts) OrNil() *Facts {
	if f == nil || f.Usage == "" && f.Company == "" && f.Score == nil && f.Level == nil && len(f.Flags) == 0 {
		return nil
	}
	return f
}

func NormalizeUsage(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	has := func(subs ...string) bool {
		for _, sub := range subs {
			if strings.Contains(s, sub) {
				return true
			}
		}
		return false
	}
	switch {
	case s == "":
		return ""
	case has("mobile", "wireless", "cellular"):
		return "mobile"
	case s == "cdn" || has("content delivery"):
		return "cdn"
	case has("hosting", "data center", "datacenter"):
		return "hosting"
	case s == "isp" || s == "residential" || has("fixed line", " isp"):
		return "isp"
	case s == "business" || s == "commercial" || s == "corporate" || s == "organization" || s == "banking":
		return "business"
	case s == "education" || s == "edu" || has("university", "school", "library"):
		return "education"
	case s == "government" || s == "gov" || s == "military":
		return "government"
	}
	return ""
}
