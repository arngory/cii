package refdata

import (
	_ "embed"
	"strings"
	"sync"
	"unicode"
)

//go:generate go run ../../tools/gendata -out .

//go:embed countries.tsv
var countriesTSV string

//go:embed iata.tsv
var iataTSV string

var (
	once     sync.Once
	names    map[string]string
	byName   map[string]string
	iataToCC map[string]string
)

func load() {
	names = map[string]string{}
	byName = map[string]string{}
	iataToCC = map[string]string{}
	for _, line := range strings.Split(countriesTSV, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		names[f[0]] = f[1]
		byName[normalize(f[1])] = f[0]
		if len(f) > 2 && f[2] != "" {
			for _, alt := range strings.Split(f[2], "|") {
				byName[normalize(alt)] = f[0]
			}
		}
	}
	for _, line := range strings.Split(iataTSV, "\n") {
		if code, cc, ok := strings.Cut(line, "\t"); ok {
			iataToCC[code] = cc
		}
	}
}

func normalize(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}), " ")
}

func CountryName(cc string) string {
	once.Do(load)
	return names[strings.ToUpper(cc)]
}

func CountryByName(name string) string {
	once.Do(load)
	return byName[normalize(name)]
}

func IATACountry(code string) string {
	once.Do(load)
	return iataToCC[strings.ToUpper(code)]
}

func IsCountry(cc string) bool {
	return CountryName(cc) != ""
}
