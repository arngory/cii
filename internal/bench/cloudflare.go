package bench

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/arngory/cii/internal/netx"
)

type Speed struct {
	Server      string  `json:"server"`
	Colo        string  `json:"colo,omitempty"`
	LatencyMs   float64 `json:"latency_ms"`
	DownMbps    float64 `json:"download_mbps"`
	UpMbps      float64 `json:"upload_mbps"`
	DownBytes   int64   `json:"download_bytes"`
	UpBytes     int64   `json:"upload_bytes"`
	DurationSec float64 `json:"duration_seconds"`
}

func CloudflareSpeed(ctx context.Context, n *netx.Net, dur time.Duration) (Speed, error) {
	client := n.HTTPClient(Module)
	client.Timeout = 0
	return cloudflareSpeed(ctx, client, "https://"+cloudflareSpeedHost, dur)
}

func cloudflareSpeed(ctx context.Context, client *http.Client, base string, dur time.Duration) (Speed, error) {
	if dur <= 0 {
		dur = 5 * time.Second
	}
	s := Speed{Server: cloudflareSpeedHost}
	start := time.Now()

	lat, colo, err := cfLatency(ctx, client, base+"/cdn-cgi/trace")
	if err != nil {
		return s, err
	}
	s.LatencyMs, s.Colo = lat, colo

	down, bytesDown, err := cfDownload(ctx, client, base+"/__down?bytes=", dur)
	if err != nil {
		return s, err
	}
	s.DownMbps, s.DownBytes = down, bytesDown

	up, bytesUp, err := cfUpload(ctx, client, base+"/__up", dur)
	if err != nil {
		return s, err
	}
	s.UpMbps, s.UpBytes = up, bytesUp
	s.DurationSec = time.Since(start).Seconds()
	return s, nil
}

func cfLatency(ctx context.Context, c *http.Client, traceURL string) (float64, string, error) {
	best := -1.0
	colo := ""
	for i := 0; i < 5; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
		if err != nil {
			return 0, "", err
		}
		t := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		ms := float64(time.Since(t).Microseconds()) / 1000
		if best < 0 || ms < best {
			best = ms
		}
		if colo == "" {
			for _, line := range strings.Split(string(body), "\n") {
				if v, ok := strings.CutPrefix(line, "colo="); ok {
					colo = strings.TrimSpace(v)
				}
			}
		}
	}
	return best, colo, nil
}

const (
	cfDownFirst = 1 << 20
	cfDownLimit = 50 << 20
	cfUpFirst   = 256 << 10
	cfUpLimit   = 25 << 20
	cfUpGrace   = 10 * time.Second
	cfBackoff   = 250 * time.Millisecond
)

type cfChunk struct {
	bytes  int64
	took   time.Duration
	status int
}

type cfTransfer func(ctx context.Context, size int64) (cfChunk, error)

func cfMeasure(ctx context.Context, phase string, dur, grace time.Duration, first, limit int64, do cfTransfer) (float64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, dur+grace)
	defer cancel()
	deadline := time.Now().Add(dur)
	size, backoff := first, cfBackoff
	var total int64
	var active time.Duration
	rejected := 0
	for time.Now().Before(deadline) && ctx.Err() == nil {
		chunk, err := do(ctx, size)
		if err != nil && ctx.Err() == nil {
			return 0, 0, fmt.Errorf("%s: %w", phase, err)
		}
		if err == nil && chunk.status >= 400 {
			rejected = chunk.status
			limit = max(size/2, first)
			size = limit
			select {
			case <-ctx.Done():
			case <-time.After(min(backoff, time.Until(deadline))):
			}
			backoff = min(backoff*2, time.Second)
			continue
		}
		total += chunk.bytes
		active += chunk.took
		if err != nil {
			break
		}
		backoff = cfBackoff
		if chunk.took < time.Until(deadline)/4 {
			size = min(size*2, limit)
		}
	}
	if total == 0 {
		if rejected != 0 {
			return 0, 0, fmt.Errorf("%s: HTTP %d", phase, rejected)
		}
		return 0, 0, fmt.Errorf("%s: nothing transferred in %s", phase, dur+grace)
	}
	return mbit(total, active), total, nil
}

func cfDownload(ctx context.Context, c *http.Client, downURL string, dur time.Duration) (float64, int64, error) {
	return cfMeasure(ctx, "download", dur, 0, cfDownFirst, cfDownLimit, func(ctx context.Context, size int64) (cfChunk, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%d", downURL, size), nil)
		if err != nil {
			return cfChunk{}, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return cfChunk{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			return cfChunk{status: resp.StatusCode}, nil
		}
		t := time.Now()
		n, err := io.Copy(io.Discard, resp.Body)
		return cfChunk{bytes: n, took: time.Since(t), status: resp.StatusCode}, err
	})
}

func cfUpload(ctx context.Context, c *http.Client, upURL string, dur time.Duration) (float64, int64, error) {
	return cfMeasure(ctx, "upload", dur, cfUpGrace, cfUpFirst, cfUpLimit, func(ctx context.Context, size int64) (cfChunk, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, &zeroReader{n: size})
		if err != nil {
			return cfChunk{}, err
		}
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
		t := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			return cfChunk{}, err
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode >= 400 {
			return cfChunk{status: resp.StatusCode}, nil
		}
		return cfChunk{bytes: size, took: time.Since(t), status: resp.StatusCode}, nil
	})
}

type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	clear(p)
	z.n -= int64(len(p))
	return len(p), nil
}

func mbit(b int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(b) * 8 / 1e6 / d.Seconds()
}
