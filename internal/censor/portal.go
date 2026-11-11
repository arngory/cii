package censor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/arngory/cii/internal/probe"
)

const Portal probe.Group = "portal"

type endpoint struct {
	Name   string
	URL    string
	Status int
	Body   string
}

var portalEndpoints = []endpoint{
	{"Google", "http://connectivitycheck.gstatic.com/generate_204", http.StatusNoContent, ""},
	{"Google HTTPS", "https://connectivitycheck.gstatic.com/generate_204", http.StatusNoContent, ""},
	{"Cloudflare", "http://cp.cloudflare.com/generate_204", http.StatusNoContent, ""},
	{"Cloudflare HTTPS", "https://cp.cloudflare.com/generate_204", http.StatusNoContent, ""},
	{"Apple", "http://captive.apple.com/hotspot-detect.html", http.StatusOK, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"},
	{"Microsoft NCSI", "http://www.msftconnecttest.com/connecttest.txt", http.StatusOK, "Microsoft Connect Test"},
	{"Microsoft Edge", "http://edge-http.microsoft.com/captiveportal/generate_204", http.StatusNoContent, ""},
	{"Firefox", "http://detectportal.firefox.com/success.txt", http.StatusOK, "success"},
	{"Ubuntu", "http://connectivity-check.ubuntu.com/", http.StatusNoContent, ""},
	{"Arch Linux", "http://ping.archlinux.org/", http.StatusOK, "This domain is used for connectivity checking (captive portal detection)."},
}

func (r *runner) portal(ctx context.Context) []probe.Result {
	out := make([]probe.Result, len(portalEndpoints))
	var wg sync.WaitGroup
	for i, e := range portalEndpoints {
		wg.Go(func() {
			defer r.acquire()()
			var res probe.Result
			err := r.attempt(func() error {
				var err error
				res, err = r.fetchPortal(ctx, e)
				return err
			})
			if err != nil {
				res = probe.Result{Status: errStatus(err), Reason: describe(err)}
				if isX509(err) {
					res.Status, res.Reason = probe.No, "TLS interception: invalid certificate"
				}
			}
			res.Group, res.Service = Portal, e.Name
			out[i] = res
		})
	}
	wg.Wait()
	return out
}

func (r *runner) fetchPortal(ctx context.Context, e endpoint) (probe.Result, error) {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	c := r.n.HTTPClient(Module)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return probe.Result{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return probe.Result{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return probe.Result{}, err
	}
	return judgePortal(e, resp.StatusCode, resp.Header.Get("Location"), body), nil
}

func judgePortal(e endpoint, status int, location string, body []byte) probe.Result {
	got := bytes.TrimSpace(body)
	switch {
	case status >= 300 && status < 400:
		res := probe.Result{Status: probe.No, Reason: fmt.Sprintf("redirected (HTTP %d): captive portal or filter page", status)}
		if u, err := url.Parse(location); err == nil && u.Host != "" {
			res.Detail = "to " + u.Host
		}
		return res
	case status >= 500:
		return probe.Result{Status: probe.Unknown, Reason: fmt.Sprintf("HTTP %d from the path or the server", status)}
	case status != e.Status && e.Status == http.StatusNoContent && status == http.StatusOK:
		return probe.Result{Status: probe.No, Reason: "altered: HTTP 200 instead of 204, a proxy rewrote the answer", Detail: snippet(got)}
	case status != e.Status:
		return probe.Result{Status: probe.No, Reason: fmt.Sprintf("altered: HTTP %d instead of %d", status, e.Status), Detail: snippet(got)}
	case e.Status == http.StatusNoContent && len(got) > 0:
		return probe.Result{Status: probe.No, Reason: "altered: body added to an empty answer", Detail: snippet(got)}
	case e.Body != "" && string(got) != e.Body:
		return probe.Result{Status: probe.No, Reason: "altered: body differs from the vendor's", Detail: snippet(got)}
	}
	return probe.Result{Status: probe.Yes, Reason: "matches the vendor's answer"}
}

func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	return probe.Truncate(s, 60)
}
