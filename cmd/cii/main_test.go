package main

import "testing"

func TestParseSize(t *testing.T) {
	good := map[string]int64{
		"1":                   1,
		"4k":                  4 << 10,
		" 64M ":               64 << 20,
		"1G":                  1 << 30,
		"8589934591G":         8589934591 << 30,
		"9223372036854775807": 9223372036854775807,
	}
	for in, want := range good {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "x", "0", "-1G", "G", "1T", "8589934592G", "9999999999G", "9007199254740992K", "99999999999999999999"} {
		if got, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) = %d, want error", in, got)
		}
	}
}
