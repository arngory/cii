package region

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

var ExtendedChecks = []probe.Check{
	{Service: "Twitch", Group: Platform, Tier: probe.TierB,
		Requests: []probe.Request{{Method: http.MethodPost, URL: "https://gql.twitch.tv/gql", Body: clientids.TwitchQuery,
			Header: map[string]string{"Client-Id": clientids.TwitchClientID, "Content-Type": "application/json"}}},
		Eval: probe.CountryFrom(probe.JSONPath("[0].data.requestInfo.countryCode"), 0)},
	{Service: "ChatGPT", Group: Platform, Tier: probe.TierB,
		Requests: []probe.Request{{Method: http.MethodPost, URL: "https://ab.chatgpt.com/v1/initialize",
			Header: map[string]string{"Statsig-Api-Key": clientids.ChatGPTStatsigKey}}},
		Eval: probe.CountryFrom(probe.BodyRegex(`"derived_fields":\{[^}]*"country":"([^"]*)"`), 0)},
	{Service: "Claude", Group: Platform, Tier: probe.TierB,
		Requests: []probe.Request{{URL: "https://claude.ai/api/bootstrap",
			Header: map[string]string{"User-Agent": clientids.ClaudeAndroidUA, "Anthropic-Client-Platform": clientids.ClaudePlatformHeader}}},
		Eval: probe.CountryFrom(probe.JSONPath("statsig.user.country"), 0)},
	{Service: "Netflix", Group: Platform, Tier: probe.TierB, Requests: probe.Get(fastURL), Eval: netflixFast},
	{Service: "Spotify", Group: Platform, Tier: probe.TierB, Requests: spotifySignup(),
		Eval: probe.CountryFrom(probe.JSONPath("country"), 0)},
	{Service: "Disney+", Group: Platform, Tier: probe.TierB, Requests: disneyPlusGraph(),
		Eval: probe.CountryFrom(probe.JSONPath("extensions.sdk.session.location.countryCode"), 0)},
}

const fastURL = "https://api.fast.com/netflix/speedtest/v2?https=true&urlCount=1&token=" + clientids.FastToken

func spotifySignup() []probe.Request {
	return []probe.Request{{
		URL:    "https://spclient.wg.spotify.com/signup/public/v1/account/?validate=1&key=" + clientids.SpotifySignupKey,
		Header: map[string]string{"X-Client-Id": clientids.SpotifyClientID},
	}}
}

func disneyPlusGraph() []probe.Request {
	return []probe.Request{{Method: http.MethodPost, URL: "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql",
		Body:   clientids.DisneyPlusQuery,
		Header: map[string]string{"Authorization": "Bearer " + clientids.DisneyPlusAPIKey, "Content-Type": "application/json"}}}
}

var netflixNode = regexp.MustCompile(`^https://ipv[46]-([a-z0-9]+-([a-z]{3})[0-9]+[a-z0-9-]*)\.`)

func netflixFast(rs []*probe.Response) []probe.Result {
	r := rs[0]
	client := probe.CountryResult(probe.JSONPath("client.location.country")(r), r.Status)
	cdn := probe.Result{Group: CDN, Service: "Netflix", Status: probe.Unknown}
	if m := netflixNode.FindStringSubmatch(probe.JSONPath("targets[0].url")(r)); m != nil {
		cdn.Node, cdn.IATA = m[1], strings.ToUpper(m[2])
	}
	if loc := probe.CountryResult(probe.JSONPath("targets[0].location.country")(r), r.Status); loc.Status == probe.OK {
		cdn.Status, cdn.Country = probe.OK, loc.Country
	}
	return []probe.Result{client, cdn}
}
