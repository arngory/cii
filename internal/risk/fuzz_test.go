package risk

import (
	"bytes"
	"testing"
)

func FuzzDataParsers(f *testing.F) {
	for _, seed := range []string{"", "1.2.3.0/24\n", `{"prefixes":[{"ip_prefix":"1.2.3.0/24","region":"x","service":"EC2"}]}`, `{"prefixes":[{"ipv4Prefix":"1.2.3.0/24","scope":"x"}]}`,
		`{"regions":[{"region":"x","cidrs":[{"cidr":"1.2.3.0/24","tags":["OCI"]}]}]}`, "1.2.3.0/24,DE,DE-BE,Berlin,\n", "#comment\n\n::/0\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, s := range DataSources {
			s.parse(bytes.NewReader(data), func(prefix, label string) {})
		}
	})
}
