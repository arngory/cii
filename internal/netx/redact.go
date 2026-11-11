package netx

import (
	"errors"
	"net/url"
	"strings"
)

var secretParams = []string{"token", "key", "secret", "auth", "sig", "password", "pass"}

func StripSecrets(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	q := u.Query()
	for k := range q {
		lk := strings.ToLower(k)
		for _, s := range secretParams {
			if strings.Contains(lk, s) {
				q.Set(k, "REDACTED")
				break
			}
		}
	}
	u.RawQuery = q.Encode()
	u.User = nil
	return u.String()
}

func Redact(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	return &url.Error{Op: ue.Op, URL: StripSecrets(ue.URL), Err: ue.Err}
}
