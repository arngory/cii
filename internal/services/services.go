package services

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
)

const Module = "services"

const (
	Streaming probe.Group = "streaming"
	AI        probe.Group = "ai"
	Web       probe.Group = "web"
)

func Select(k config.Keys, extended bool) []probe.Check {
	return probe.Select(Module, Checks, k, extended)
}

var Checks = []probe.Check{
	{Service: "Netflix", Group: Streaming, Requests: append(probe.Get("https://www.netflix.com/title/81280792"), probe.Get("https://www.netflix.com/title/70143836")...), Eval: netflix},
	{Service: "Prime Video", Group: Streaming, Requests: probe.Get("https://www.primevideo.com/"), Eval: primeVideo},
	{Service: "Reddit", Group: Web, Requests: probe.Get("https://www.reddit.com/"), Eval: reddit},
	{Service: "Wikipedia editing", Group: Web, Requests: probe.Get("https://en.wikipedia.org/w/api.php?action=query&meta=userinfo&uiprop=blockinfo&format=json"), Eval: wikipedia},

	{Service: "ChatGPT app", Group: AI, Requests: probe.Get("https://ios.chat.openai.com/"), Eval: chatGPTApp},
	{Service: "NotebookLM", Group: AI, Requests: probe.Get("https://notebooklm.google.com/"),
		ExtraHosts: []string{"notebook.google.com", "accounts.google.com"}, Eval: notebookLM},
	{Service: "Gemini API", Group: AI, Requests: probe.Get("https://generativelanguage.googleapis.com/v1beta/models"),
		KeyOK:     func(k config.Keys) bool { return k.GeminiAPIKey != "" },
		Authorize: func(req *http.Request, k config.Keys) { req.Header.Set("X-Goog-Api-Key", k.GeminiAPIKey) },
		Eval:      geminiAPI},
	aiAPI("OpenAI API", "https://api.openai.com/v1/models", "unsupported_country_region_territory"),
	aiAPI("Anthropic API", "https://api.anthropic.com/v1/models", "Request not allowed"),
	aiAPI("Grok API", "https://api.x.ai/v1/models", "not available in your region"),
	aiAPI("Mistral API", "https://api.mistral.ai/v1/models", ""),
	aiAPI("Groq API", "https://api.groq.com/openai/v1/models", ""),
	aiAPI("Cohere API", "https://api.cohere.com/v1/models", ""),
	aiAPI("DeepSeek API", "https://api.deepseek.com/models", ""),
	aiAPI("Qwen API", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models", ""),
	aiAPI("Qwen API (CN)", "https://dashscope.aliyuncs.com/compatible-mode/v1/models", ""),
	aiAPI("Kimi API", "https://api.moonshot.ai/v1/models", ""),
	aiAPI("Kimi API (CN)", "https://api.moonshot.cn/v1/models", ""),
	aiAPI("GLM API", "https://api.z.ai/api/paas/v4/models", ""),
	aiAPI("GLM API (CN)", "https://open.bigmodel.cn/api/paas/v4/models", ""),
	aiAPI("MiniMax API", "https://api.minimax.io/v1/models", ""),
	aiAPI("MiniMax API (CN)", "https://api.minimaxi.com/v1/models", ""),
	aiAPI("Doubao API (CN)", "https://ark.cn-beijing.volces.com/api/v3/models", ""),
	aiAPI("SiliconFlow API (CN)", "https://api.siliconflow.cn/v1/models", ""),

	{Service: "Disney+", Group: Streaming, Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
		URL: "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql", Body: clientids.DisneyPlusQuery,
		Header: map[string]string{"Authorization": "Bearer " + clientids.DisneyPlusAPIKey, "Content-Type": "application/json"}}},
		Eval: withPlatformCountry("Disney+", disneyPlus)},
	{Service: "Spotify signup", Group: Streaming, Tier: probe.TierB, Requests: []probe.Request{{
		URL:    "https://spclient.wg.spotify.com/signup/public/v1/account/?validate=1&key=" + clientids.SpotifySignupKey,
		Header: map[string]string{"X-Client-Id": clientids.SpotifyClientID}}},
		Eval: withPlatformCountry("Spotify", spotify)},
	{Service: "YouTube Premium", Group: Streaming, Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
		URL: "https://www.youtube.com/youtubei/v1/browse", Body: clientids.YouTubePremiumQuery,
		Header: map[string]string{"Content-Type": "application/json"}}}, Eval: youtubePremium},
	{Service: "DAZN", Group: Streaming, Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
		URL: "https://startup.core.indazn.com/misl/v5/Startup", Body: clientids.DAZNStartupBody,
		Header: map[string]string{"Content-Type": "application/json"}}}, Eval: dazn},
}

func withPlatformCountry(service string, eval func([]*probe.Response) []probe.Result) func([]*probe.Response) []probe.Result {
	return func(rs []*probe.Response) []probe.Result {
		out := eval(rs)
		platform := probe.Result{Group: region.Platform, Service: service, Status: probe.Unknown}
		if out[0].Country != "" {
			platform.Status, platform.Country = probe.OK, out[0].Country
		}
		return append(out, platform)
	}
}

func aiAPI(service, rawURL, blockedMarker string) probe.Check {
	return probe.Check{Service: service, Group: AI, Requests: probe.Get(rawURL), Eval: func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		switch {
		case r.Status == http.StatusUnauthorized:
			return yes("")
		case r.Status == http.StatusForbidden && blockedMarker != "" && bytes.Contains(r.Body, []byte(blockedMarker)):
			return []probe.Result{{Status: probe.No, Reason: "region not supported"}}
		case r.Status == http.StatusForbidden:
			return []probe.Result{{Status: probe.IPBlock, Reason: "HTTP 403"}}
		}
		return unknown(r)
	}}
}

var chatGPTBlockType = probe.JSONPath("type")

func chatGPTApp(rs []*probe.Response) []probe.Result {
	r := rs[0]
	lower := bytes.ToLower(r.Body)
	switch {
	case bytes.Contains(r.Body, []byte(`"cf_details"`)):
		reason := "refused a client that is not the app"
		if t := chatGPTBlockType(r); t != "" {
			reason += " (type " + t + ")"
		}
		return []probe.Result{{Status: probe.Unknown, Reason: reason}}
	case bytes.Contains(lower, []byte("disallowed isp")):
		return []probe.Result{{Status: probe.IPBlock, Reason: "disallowed ISP"}}
	case bytes.Contains(lower, []byte("unsupported_country")):
		return no("region not supported")
	case r.Status < 400:
		return yes("")
	}
	return unknown(r)
}

func notebookLM(rs []*probe.Response) []probe.Result {
	r := rs[0]
	u, err := url.Parse(r.URL)
	switch {
	case err != nil:
		return unknown(r)
	case strings.Contains(u.RawQuery, "location=unsupported"):
		return no("region not supported")
	case r.Status != http.StatusOK:
		return unknown(r)
	case u.Host == "accounts.google.com", u.Host == "notebook.google.com", u.Host == "notebooklm.google.com":
		return yes("")
	}
	return []probe.Result{{Status: probe.Unknown, Reason: "unexpected destination " + u.Host}}
}

func geminiAPI(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case r.Status == http.StatusOK:
		return yes("")
	case bytes.Contains(r.Body, []byte("User location is not supported")):
		return no("region not supported")
	case bytes.Contains(r.Body, []byte("API key not valid")), bytes.Contains(r.Body, []byte("API_KEY_INVALID")):
		return probe.Fail("key rejected")
	}
	return unknown(r)
}

func yes(country string) []probe.Result {
	return []probe.Result{{Status: probe.Yes, Country: country}}
}

func no(reason string) []probe.Result {
	return []probe.Result{{Status: probe.No, Reason: reason}}
}

func unknown(r *probe.Response) []probe.Result {
	if f, failed := probe.HTTPFailure(r.Status); failed {
		return []probe.Result{f}
	}
	return []probe.Result{{Status: probe.Unknown}}
}

func countryOf(r *probe.Response, extract func(*probe.Response) string) string {
	if c := probe.CountryResult(extract(r), r.Status); c.Status == probe.OK {
		return c.Country
	}
	return ""
}

var netflixCountry = probe.BodyRegex(`"requestCountry":\{[^}]*"id":"([A-Z]{2})"`)

func netflix(rs []*probe.Response) []probe.Result {
	for _, r := range rs {
		if f, failed := probe.HTTPFailure(r.Status); failed && r.Status != http.StatusNotFound {
			return []probe.Result{f}
		}
	}
	missing := 0
	for _, r := range rs {
		if r.Status == http.StatusNotFound || bytes.Contains(r.Body, []byte("Oh no!")) {
			missing++
		}
	}
	cc := countryOf(rs[0], netflixCountry)
	switch missing {
	case 0, 1:
		return yes(cc)
	}
	if cc == "" {
		return no("titles unavailable")
	}
	return []probe.Result{{Status: probe.Partial, Country: cc, Reason: "originals only"}}
}

var primeTerritory = probe.BodyRegex(`"currentTerritory":"([A-Z]{2})"`)

func primeVideo(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if bytes.Contains(r.Body, []byte("isServiceRestricted")) {
		return no("service restricted")
	}
	if cc := countryOf(r, primeTerritory); cc != "" {
		return yes(cc)
	}
	return unknown(r)
}

func reddit(rs []*probe.Response) []probe.Result {
	switch rs[0].Status {
	case http.StatusOK:
		return yes("")
	case http.StatusForbidden:
		return []probe.Result{{Status: probe.IPBlock, Reason: "HTTP 403"}}
	}
	return unknown(rs[0])
}

var wikiBlock = regexp.MustCompile(`"blockid":\d+`)

func wikipedia(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if r.Status != http.StatusOK || !bytes.Contains(r.Body, []byte(`"userinfo"`)) {
		return unknown(r)
	}
	if wikiBlock.Match(r.Body) {
		reason := probe.Truncate(probe.JSONPath("query.userinfo.blockreason")(r), 80)
		return []probe.Result{{Status: probe.IPBlock, Reason: "editing blocked: " + reason}}
	}
	return yes("")
}

func disneyPlus(rs []*probe.Response) []probe.Result {
	r := rs[0]
	cc := countryOf(r, probe.JSONPath("extensions.sdk.session.location.countryCode"))
	switch {
	case bytes.Contains(r.Body, []byte(`"inSupportedLocation":true`)):
		return yes(cc)
	case bytes.Contains(r.Body, []byte(`"inSupportedLocation":false`)), bytes.Contains(r.Body, []byte("Forbidden location")):
		return []probe.Result{{Status: probe.No, Country: cc}}
	}
	return unknown(r)
}

var spotifyBlocked = regexp.MustCompile(`"status":\s*(120|320)\b`)

func spotify(rs []*probe.Response) []probe.Result {
	r := rs[0]
	cc := countryOf(r, probe.JSONPath("country"))
	switch {
	case spotifyBlocked.Match(r.Body), bytes.Contains(r.Body, []byte(`"is_country_launched":false`)):
		return []probe.Result{{Status: probe.No, Country: cc}}
	case bytes.Contains(r.Body, []byte(`"is_country_launched":true`)):
		return yes(cc)
	}
	return unknown(r)
}

func youtubePremium(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if r.Status != http.StatusOK {
		return unknown(r)
	}
	switch {
	case bytes.Contains(r.Body, []byte("Premium is not available in your country")):
		return no("")
	case bytes.Contains(r.Body, []byte("premiumPurchaseButtonRenderer")):
		return yes("")
	}
	return unknown(r)
}

var daznAllowed = regexp.MustCompile(`"isAllowed"\s*:\s*(true|false)`)

func dazn(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if bytes.Contains(bytes.ToLower(r.Body), []byte("security policy has been breached")) {
		return []probe.Result{{Status: probe.IPBlock, Reason: "security policy"}}
	}
	cc := countryOf(r, probe.BodyRegex(`"GeolocatedCountry"\s*:\s*"([A-Za-z]{2})"`))
	if m := daznAllowed.FindSubmatch(r.Body); m != nil {
		if string(m[1]) == "true" {
			return yes(cc)
		}
		return []probe.Result{{Status: probe.No, Country: cc}}
	}
	return unknown(r)
}
