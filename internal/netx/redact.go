package netx

import (
	"errors"
	"fmt"
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

func Redact(err error, raw string) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, StripSecrets(ue.URL), ue.Err)
	}
	return errors.New(strings.ReplaceAll(err.Error(), raw, StripSecrets(raw)))
}
