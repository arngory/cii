package probe

import "testing"

func TestNormalizeUsage(t *testing.T) {
	for in, want := range map[string]string{
		"isp": "isp", "Residential": "isp", "Fixed Line ISP": "isp",
		"Mobile ISP": "mobile", "Wireless": "mobile",
		"Data Center/Web Hosting/Transit": "hosting", "hosting": "hosting", "Data Center": "hosting",
		"Content Delivery Network": "cdn", "Commercial": "business", "Corporate": "business", "business": "business",
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
