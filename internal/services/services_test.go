package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func r(status int, body string) *probe.Response {
	return &probe.Response{Status: status, Body: []byte(body)}
}

func eval(t *testing.T, name string) func([]*probe.Response) []probe.Result {
	t.Helper()
	for _, c := range Checks {
		if c.Service == name {
			return c.Eval
		}
	}
	t.Fatalf("no check %q", name)
	return nil
}

func TestAIAPI(t *testing.T) {
	openai := eval(t, "OpenAI API")
	cases := []struct {
		resp *probe.Response
		want probe.Status
	}{
		{r(401, `{"error":"Missing bearer"}`), probe.Yes},
		{r(403, `{"error":{"code":"unsupported_country_region_territory"}}`), probe.No},
		{r(403, `<html>denied</html>`), probe.IPBlock},
		{r(429, ``), probe.Failed},
		{r(200, `{}`), probe.Unknown},
	}
	for _, c := range cases {
		if got := openai([]*probe.Response{c.resp})[0].Status; got != c.want {
			t.Errorf("OpenAI %d %q = %s, want %s", c.resp.Status, c.resp.Body, got, c.want)
		}
	}
	if got := eval(t, "Kimi API")([]*probe.Response{r(403, `unsupported_country_region_territory`)})[0].Status; got != probe.IPBlock {
		t.Errorf("reachability-only 403 = %s", got)
	}
}

func TestNetflix(t *testing.T) {
	page := `{"requestCountry":{"supportedLocales":["en"],"id":"US","countryName":"United States"}}`
	nf := eval(t, "Netflix")
	if res := nf([]*probe.Response{r(200, page), r(200, page)})[0]; res.Status != probe.Yes || res.Country != "US" {
		t.Errorf("both = %+v", res)
	}
	if res := nf([]*probe.Response{r(200, page+"Oh no!"), r(404, "")})[0]; res.Status != probe.Partial || res.Country != "US" {
		t.Errorf("originals = %+v", res)
	}
	if res := nf([]*probe.Response{r(200, page), r(503, "")})[0]; res.Status != probe.Failed {
		t.Errorf("failure = %+v", res)
	}
}

func TestPageChecks(t *testing.T) {
	cases := []struct {
		service string
		resp    *probe.Response
		want    probe.Status
		country string
	}{
		{"Prime Video", r(200, `x"currentTerritory":"GB"y`), probe.Yes, "GB"},
		{"Prime Video", r(200, `{"isServiceRestricted":true}`), probe.No, ""},
		{"Reddit", r(403, ``), probe.IPBlock, ""},
		{"Reddit", r(200, ``), probe.Yes, ""},
		{"Wikipedia editing", r(200, `{"query":{"userinfo":{"id":0,"blockid":123,"blockreason":"open proxy"}}}`), probe.IPBlock, ""},
		{"Wikipedia editing", r(200, `{"query":{"userinfo":{"id":0,"name":"1.2.3.4"}}}`), probe.Yes, ""},
		{"Wikipedia editing", r(429, `too many`), probe.Failed, ""},
		{"Disney+", r(200, `{"extensions":{"sdk":{"session":{"inSupportedLocation":true,"location":{"countryCode":"FR"}}}}}`), probe.Yes, "FR"},
		{"Disney+", r(200, `{"errors":[{"message":"Forbidden location"}]}`), probe.No, ""},
		{"Spotify signup", r(200, `{"status":1,"country":"SE","is_country_launched":true}`), probe.Yes, "SE"},
		{"Spotify signup", r(200, `{"status":120}`), probe.No, ""},
		{"YouTube Premium", r(200, `..premiumPurchaseButtonRenderer..`), probe.Yes, ""},
		{"YouTube Premium", r(200, `..Premium is not available in your country..`), probe.No, ""},
		{"YouTube Premium", r(200, `{}`), probe.Unknown, ""},
		{"DAZN", r(200, `{"Region":{"isAllowed":true,"GeolocatedCountry":"de"}}`), probe.Yes, "DE"},
		{"DAZN", r(403, `Security policy has been breached`), probe.IPBlock, ""},
	}
	for _, c := range cases {
		got := eval(t, c.service)([]*probe.Response{c.resp})[0]
		if got.Status != c.want || got.Country != c.country {
			t.Errorf("%s %d = %+v, want %s %q", c.service, c.resp.Status, got, c.want, c.country)
		}
	}
}

func TestTiers(t *testing.T) {
	for _, c := range Checks {
		b := c.Tier == probe.TierB
		switch c.Service {
		case "Disney+", "Spotify signup", "YouTube Premium", "DAZN":
			if !b {
				t.Errorf("%s must be tier B", c.Service)
			}
		default:
			if b {
				t.Errorf("%s must be tier A", c.Service)
			}
		}
	}
}

func TestNewAIChecks(t *testing.T) {
	app := eval(t, "ChatGPT app")
	for _, c := range []struct {
		resp   *probe.Response
		want   probe.Status
		reason string
	}{
		{r(403, `{"cf_details":"Request is not allowed. Please try again later.", "type":"dc"}`), probe.Unknown, "refused a client that is not the app (type dc)"},
		{r(403, `Your request was blocked: disallowed ISP`), probe.IPBlock, "disallowed ISP"},
		{r(200, `<html>app</html>`), probe.Yes, ""},
		{r(503, ``), probe.Failed, "HTTP 503"},
	} {
		got := app([]*probe.Response{c.resp})[0]
		if got.Status != c.want || got.Reason != c.reason {
			t.Errorf("ChatGPT app %d %q = %+v", c.resp.Status, c.resp.Body, got)
		}
	}
	nb := eval(t, "NotebookLM")
	for _, c := range []struct {
		status int
		url    string
		want   probe.Status
	}{
		{200, "https://notebook.google.com/", probe.Yes},
		{200, "https://accounts.google.com/v3/signin/identifier?continue=x", probe.Yes},
		{200, "https://notebooklm.google.com/?location=unsupported", probe.No},
		{200, "https://www.google.com/sorry/index", probe.Unknown},
	} {
		if got := nb([]*probe.Response{{Status: c.status, URL: c.url}})[0].Status; got != c.want {
			t.Errorf("NotebookLM %s = %s, want %s", c.url, got, c.want)
		}
	}
	gem := eval(t, "Gemini API")
	for body, want := range map[string]probe.Status{
		`{"models":[]}`: probe.Yes,
		`{"error":{"code":400,"message":"User location is not supported for the API use.","status":"FAILED_PRECONDITION"}}`: probe.No,
		`{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT"}}`:    probe.Failed,
	} {
		status := 400
		if want == probe.Yes {
			status = 200
		}
		if got := gem([]*probe.Response{r(status, body)})[0].Status; got != want {
			t.Errorf("Gemini %q = %s, want %s", body, got, want)
		}
	}
}
