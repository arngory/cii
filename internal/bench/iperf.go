package bench

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arngory/cii/internal/netx"
)

type IperfServer struct {
	Host     string `json:"host"`
	Ports    string `json:"ports"`
	Provider string `json:"provider"`
	Location string `json:"location"`
	IPv6     bool   `json:"ipv6"`
}

type IperfRun struct {
	Server    IperfServer `json:"server"`
	Client    string      `json:"client"`
	Port      int         `json:"port,omitempty"`
	LatencyMs float64     `json:"latency_ms,omitempty"`
	SendMbps  float64     `json:"send_mbps,omitempty"`
	RecvMbps  float64     `json:"recv_mbps,omitempty"`
	Streams   int         `json:"streams"`
	Error     string      `json:"error,omitempty"`
}

const (
	stateTestStart       = 1
	stateTestRunning     = 2
	stateTestEnd         = 4
	stateParamExchange   = 9
	stateCreateStreams   = 10
	stateServerTerminate = 11
	stateExchangeResults = 13
	stateDisplayResults  = 14
	stateIperfDone       = 16
	stateAccessDenied    = -1
	stateServerError     = -2

	cookieSize     = 37
	iperfStreams   = 4
	iperfBlock     = 128 << 10
	iperfHandshake = 5 * time.Second
	clientVersion  = "3.17"
)

var stateNames = map[int8]string{
	0: "the greeting", stateTestStart: "TEST_START", stateTestRunning: "TEST_RUNNING", stateParamExchange: "PARAM_EXCHANGE",
	stateCreateStreams: "CREATE_STREAMS", stateExchangeResults: "EXCHANGE_RESULTS", stateDisplayResults: "DISPLAY_RESULTS",
}

const cookieAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

func makeCookie() []byte {
	c := make([]byte, cookieSize)
	rand.Read(c)
	for i := 0; i < cookieSize-1; i++ {
		c[i] = cookieAlphabet[int(c[i])%len(cookieAlphabet)]
	}
	c[cookieSize-1] = 0
	return c
}

func portRange(spec string) (int, int, error) {
	first, last, ranged := strings.Cut(spec, "-")
	if !ranged {
		last = first
	}
	lo, errLo := strconv.Atoi(first)
	hi, errHi := strconv.Atoi(last)
	if errLo != nil || errHi != nil || lo < 1 || hi > 65535 || hi < lo {
		return 0, 0, fmt.Errorf("bad port range %q", spec)
	}
	return lo, hi, nil
}

const clientNative = "cii"

func IperfTest(ctx context.Context, n *netx.Net, s IperfServer, dur time.Duration) IperfRun {
	run := IperfRun{Server: s, Client: clientNative, Streams: iperfStreams}
	if dur <= 0 {
		dur = 5 * time.Second
	}
	if n.Options().Family == netx.IPv6 && !s.IPv6 {
		run.Error = "no IPv6 endpoint"
		return run
	}
	return tryPorts(ctx, run, time.Second, func(err error) bool {
		return errors.Is(err, errBusy) || errors.Is(err, errAccessDenied) || netx.IsRefused(err)
	}, func(port int, reverse bool) (float64, float64, error) {
		return iperfOnce(ctx, n, s.Host, port, dur, reverse)
	})
}

func tryPorts(ctx context.Context, run IperfRun, pause time.Duration, retry func(error) bool, once func(port int, reverse bool) (float64, float64, error)) IperfRun {
	lo, hi, err := portRange(run.Server.Ports)
	if err != nil {
		run.Error = err.Error()
		return run
	}
	var lastErr error
	for port := lo; port <= hi; port++ {
		if ctx.Err() != nil {
			run.Error = ctx.Err().Error()
			return run
		}
		send, lat, err := once(port, false)
		if err != nil {
			lastErr = err
			if retry(err) {
				continue
			}
			break
		}
		run.Port, run.SendMbps, run.LatencyMs = port, send, lat
		time.Sleep(pause)
		recv, _, err := once(port, true)
		if err != nil {
			run.Error = "receive: " + err.Error()
			return run
		}
		run.RecvMbps = recv
		return run
	}
	if lastErr != nil {
		run.Error = lastErr.Error()
	}
	return run
}

var (
	errBusy         = errors.New("server busy")
	errAccessDenied = errors.New("access denied")
)

type dialError struct{ err error }

func (e dialError) Error() string { return "connect: " + e.err.Error() }
func (e dialError) Unwrap() error { return e.err }

type iperfParams struct {
	TCP           bool   `json:"tcp"`
	Omit          int    `json:"omit"`
	Time          int    `json:"time"`
	Parallel      int    `json:"parallel"`
	Reverse       bool   `json:"reverse,omitempty"`
	Len           int    `json:"len"`
	ClientVersion string `json:"client_version"`
}

type iperfStreamResult struct {
	ID             int     `json:"id"`
	Bytes          int64   `json:"bytes"`
	Retransmits    int     `json:"retransmits"`
	Jitter         float64 `json:"jitter"`
	Errors         int     `json:"errors"`
	OmittedErrors  int     `json:"omitted_errors"`
	Packets        int     `json:"packets"`
	OmittedPackets int     `json:"omitted_packets"`
	StartTime      float64 `json:"start_time"`
	EndTime        float64 `json:"end_time"`
}

type iperfResults struct {
	CPUTotal             float64             `json:"cpu_util_total"`
	CPUUser              float64             `json:"cpu_util_user"`
	CPUSystem            float64             `json:"cpu_util_system"`
	SenderHasRetransmits int                 `json:"sender_has_retransmits"`
	Streams              []iperfStreamResult `json:"streams"`
}

func iperfOnce(ctx context.Context, n *netx.Net, host string, port int, dur time.Duration, reverse bool) (float64, float64, error) {
	ctx, cancel := context.WithTimeout(ctx, dur+15*time.Second)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	t0 := time.Now()
	ctrl, err := n.Dial(ctx, Module, "tcp", addr)
	if err != nil {
		if errors.Is(err, netx.ErrProxyRaw) || netx.AsBlocked(err) != nil {
			return 0, 0, err
		}
		return 0, 0, dialError{err}
	}
	defer ctrl.Close()
	latency := float64(time.Since(t0).Microseconds()) / 1000
	deadline, _ := ctx.Deadline()
	ctrl.SetDeadline(time.Now().Add(iperfHandshake))
	cookie := makeCookie()
	if _, err := ctrl.Write(cookie); err != nil {
		return 0, 0, dialError{err}
	}
	greeted := false

	var streams []net.Conn
	defer func() {
		for _, c := range streams {
			c.Close()
		}
	}()
	var sent, received atomic.Int64
	var runWG sync.WaitGroup
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	started := false
	var finished atomic.Int64
	last := int8(0)
	fail := func(err error) (float64, float64, error) {
		stage := stateNames[last]
		if finished.Load() > 0 {
			stage = "TEST_END"
		}
		return 0, 0, fmt.Errorf("%w (after %s)", err, stage)
	}

	for {
		state, err := readState(ctrl)
		if err != nil {
			if !greeted {
				return 0, 0, dialError{err}
			}
			return fail(err)
		}
		last = state
		if !greeted {
			greeted = true
			ctrl.SetDeadline(deadline)
		}
		switch state {
		case stateParamExchange:
			p := iperfParams{TCP: true, Time: max(int(dur.Seconds()), 1), Parallel: iperfStreams, Reverse: reverse, Len: iperfBlock, ClientVersion: clientVersion}
			if err := writeJSON(ctrl, p); err != nil {
				return fail(err)
			}
		case stateCreateStreams:
			for i := 0; i < iperfStreams; i++ {
				c, err := n.Dial(ctx, Module, "tcp", addr)
				if err != nil {
					return fail(err)
				}
				c.SetDeadline(deadline)
				if _, err := c.Write(cookie); err != nil {
					c.Close()
					return fail(err)
				}
				streams = append(streams, c)
			}
		case stateTestStart:
		case stateTestRunning:
			if started {
				continue
			}
			started = true
			begin := time.Now()
			for _, c := range streams {
				runWG.Add(1)
				go func(c net.Conn) {
					defer runWG.Done()
					if reverse {
						drain(runCtx, c, &received)
					} else {
						pump(runCtx, c, &sent)
					}
				}(c)
			}
			go func() {
				select {
				case <-time.After(dur):
				case <-runCtx.Done():
				}
				stopRun()
				runWG.Wait()
				finished.Store(int64(time.Since(begin)))
				ctrl.Write([]byte{stateTestEnd})
			}()
		case stateExchangeResults:
			runWG.Wait()
			elapsed := time.Duration(finished.Load())
			if elapsed <= 0 {
				elapsed = dur
			}
			res := iperfResults{SenderHasRetransmits: -1, Streams: make([]iperfStreamResult, 0, len(streams))}
			if !reverse {
				res.SenderHasRetransmits = 0
			}
			per := sent.Load()
			if reverse {
				per = received.Load()
			}
			for i := range streams {
				res.Streams = append(res.Streams, iperfStreamResult{ID: i + 1, Bytes: per / int64(len(streams)), Retransmits: -1, EndTime: elapsed.Seconds()})
			}
			if err := writeJSON(ctrl, res); err != nil {
				return fail(err)
			}
			var remote iperfResults
			if err := readJSON(ctrl, &remote); err != nil {
				return fail(err)
			}
			var remoteBytes int64
			for _, s := range remote.Streams {
				remoteBytes += s.Bytes
			}
			total := remoteBytes
			if reverse {
				total = received.Load()
			}
			if total == 0 {
				return 0, latency, errBusy
			}
			return mbit(total, elapsed), latency, nil
		case stateDisplayResults:
			ctrl.Write([]byte{stateIperfDone})
			return 0, latency, errors.New("server finished before results")
		case stateIperfDone:
			return 0, latency, errors.New("unexpected IPERF_DONE")
		case stateAccessDenied:
			return 0, latency, errAccessDenied
		case stateServerError:
			var codes [2]int32
			binary.Read(ctrl, binary.BigEndian, &codes)
			if codes[0] == 10 || codes[0] == 11 {
				return 0, latency, errBusy
			}
			return 0, latency, fmt.Errorf("server error %d", codes[0])
		case stateServerTerminate:
			return 0, latency, errors.New("server terminated the test")
		default:
			return 0, latency, fmt.Errorf("unexpected iperf3 state %d", state)
		}
	}
}

func readState(c net.Conn) (int8, error) {
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	return int8(b[0]), nil
}

func writeJSON(c net.Conn, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	_, err = c.Write(append(frame, body...))
	return err
}

func readJSON(c net.Conn, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > 1<<20 {
		return fmt.Errorf("iperf3 message too large: %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func pump(ctx context.Context, c net.Conn, counter *atomic.Int64) {
	buf := make([]byte, iperfBlock)
	for i := range buf {
		buf[i] = byte(i*131 + 7)
	}
	for ctx.Err() == nil {
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Write(buf)
		counter.Add(int64(n))
		if err != nil {
			return
		}
	}
}

func drain(ctx context.Context, c net.Conn, counter *atomic.Int64) {
	buf := make([]byte, iperfBlock)
	for ctx.Err() == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		counter.Add(int64(n))
		if err != nil {
			return
		}
	}
}
