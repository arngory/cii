package censor

import (
	"net/http"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestJudgePortal(t *testing.T) {
	g204 := endpoint{"Google", "http://connectivitycheck.gstatic.com/generate_204", http.StatusNoContent, ""}
	apple := endpoint{"Apple", "http://captive.apple.com/hotspot-detect.html", http.StatusOK, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"}
	cases := []struct {
		e      endpoint
		status int
		loc    string
		body   string
		want   probe.Status
		detail string
	}{
		{g204, 204, "", "", probe.Yes, ""},
		{g204, 200, "", "<html>proxy</html>", probe.No, "<html>proxy</html>"},
		{g204, 302, "http://login.hotspot.example/portal?x=1", "", probe.No, "to login.hotspot.example"},
		{g204, 204, "", "injected", probe.No, "injected"},
		{g204, 503, "", "", probe.Unknown, ""},
		{apple, 200, "", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n", probe.Yes, ""},
		{apple, 200, "", "<html><body>Blocked by policy</body></html>", probe.No, "<html><body>Blocked by policy</body></html>"},
		{apple, 403, "", "denied", probe.No, "denied"},
	}
	for i, c := range cases {
		got := judgePortal(c.e, c.status, c.loc, []byte(c.body))
		if got.Status != c.want || got.Detail != c.detail {
			t.Errorf("case %d: %+v", i, got)
		}
	}
}
