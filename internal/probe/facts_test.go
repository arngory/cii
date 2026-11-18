package probe

import "testing"

func TestNormalizeUsage(t *testing.T) {
	for in, want := range map[string]string{
		"isp": "isp", "Residential": "isp", "Fixed Line ISP": "isp",
		"Mobile ISP": "mobile", "Wireless": "mobile",
		"Data Center/Web Hosting/Transit": "hosting", "hosting": "hosting", "Data Center": "hosting",
		"Content Delivery Network": "cdn", "Commercial": "business", "Corporate": "business", "business": "business", "banking": "business",
		"University/College/School": "education", "edu": "education", "Military": "government",
		"VPN": "", "TOR": "", "": "",
	} {
		if got := NormalizeUsage(in); got != want {
			t.Errorf("NormalizeUsage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFacts(t *testing.T) {
	var f Facts
	if f.OrNil() != nil {
		t.Fatal("empty facts kept")
	}
	yes, no := true, false
	f.SetIf(Proxy, nil)
	f.SetIf(Tor, &no)
	f.SetIf(Tor, &yes)
	f.SetIf(Tor, &no)
	f.SetScore(123.4)
	if _, ok := f.Flags[Proxy]; ok || !f.Flags[Tor] || *f.Score != 100 || f.OrNil() == nil {
		t.Fatalf("facts = %+v", f)
	}
	f.SetScore(-3)
	if *f.Score != 0 {
		t.Fatalf("score = %d", *f.Score)
	}
}

func TestLevels(t *testing.T) {
	for _, c := range []struct {
		score float64
		want  int
	}{{0, 0}, {20, 1}, {40, 2}, {70, 3}} {
		if got := LevelByThresholds(c.score, 1, 34, 67); got != c.want {
			t.Errorf("LevelByThresholds(%v) = %d, want %d", c.score, got, c.want)
		}
	}
	var f Facts
	f.SetLevelName(" Very High ")
	if f.Level == nil || *f.Level != 4 {
		t.Errorf("level = %v", f.Level)
	}
	f.SetLevelName("unknown")
	if *f.Level != 4 {
		t.Error("unknown label changed the level")
	}
}
