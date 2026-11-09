package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/arngory/cii/internal/netx"
)

const clientSystem = "iperf3"

type iperf3Output struct {
	Start struct {
		Connected []struct {
			RemotePort int `json:"remote_port"`
		} `json:"connected"`
	} `json:"start"`
	End struct {
		SumSent struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_sent"`
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
	Error string `json:"error"`
}

func SystemIperf3(ctx context.Context, env Env, path string, s IperfServer, dur time.Duration) IperfRun {
	run := IperfRun{Server: s, Client: clientSystem, Streams: iperfStreams}
	if env.Net.Options().Family == netx.IPv6 && !s.IPv6 {
		run.Error = "no IPv6 endpoint"
		return run
	}
	if _, err := env.Net.LookupHost(ctx, Module, s.Host); err != nil {
		run.Error = err.Error()
		return run
	}
	lo, hi, err := portRange(s.Ports)
	if err != nil {
		run.Error = err.Error()
		return run
	}
	purpose := Module + ": iperf3 " + s.Provider + ", " + s.Location
	var lastErr error
	for port := lo; port <= hi; port++ {
		if ctx.Err() != nil {
			run.Error = ctx.Err().Error()
			return run
		}
		env.Ledger.Request(Module, purpose, s.Host, "tcp")
		send, err := iperf3Once(ctx, env, path, s.Host, port, dur, false)
		if err != nil {
			lastErr = err
			if isIperfRetryable(err) {
				continue
			}
			break
		}
		run.Port, run.SendMbps = port, send
		recv, err := iperf3Once(ctx, env, path, s.Host, port, dur, true)
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

func isIperfRetryable(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "busy") || strings.Contains(msg, "refused") || strings.Contains(msg, "access denied")
}

func iperf3Once(ctx context.Context, env Env, path, host string, port int, dur time.Duration, reverse bool) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, dur+20*time.Second)
	defer cancel()
	args := iperf3Args(env.Net.Options(), host, port, dur, reverse)
	out, err := exec.CommandContext(ctx, path, args...).Output()
	var res iperf3Output
	if jerr := json.Unmarshal(out, &res); jerr != nil {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("iperf3: %w", jerr)
	}
	if res.Error != "" {
		return 0, errors.New(res.Error)
	}
	bps := res.End.SumSent.BitsPerSecond
	if reverse {
		bps = res.End.SumReceived.BitsPerSecond
	}
	if bps == 0 {
		return 0, errBusy
	}
	return bps / 1e6, nil
}

func iperf3Args(o netx.Options, host string, port int, dur time.Duration, reverse bool) []string {
	seconds := max(int(dur.Seconds()), 1)
	args := []string{"-c", host, "-p", strconv.Itoa(port), "-P", strconv.Itoa(iperfStreams), "-t", strconv.Itoa(seconds), "-J"}
	switch o.Family {
	case netx.IPv4:
		args = append(args, "-4")
	case netx.IPv6:
		args = append(args, "-6")
	}
	if o.Source.IsValid() {
		args = append(args, "-B", o.Source.String())
	}
	if reverse {
		args = append(args, "-R")
	}
	return args
}

type FioResult struct {
	Job       string  `json:"job"`
	ReadMBps  float64 `json:"read_mbps"`
	WriteMBps float64 `json:"write_mbps"`
	ReadIOPS  float64 `json:"read_iops"`
	WriteIOPS float64 `json:"write_iops"`
}

type FioReport struct {
	Version string      `json:"version"`
	Jobs    []FioResult `json:"jobs"`
}

type fioOutput struct {
	Version string `json:"fio version"`
	Jobs    []struct {
		Name  string  `json:"jobname"`
		Read  fioSide `json:"read"`
		Write fioSide `json:"write"`
	} `json:"jobs"`
}

type fioSide struct {
	BWBytes float64 `json:"bw_bytes"`
	IOPS    float64 `json:"iops"`
}

var fioJobs = []struct {
	name, rw, bs string
	depth, jobs  int
}{
	{"seq-1m", "rw", "1m", 64, 2},
	{"rand-4k", "randrw", "4k", 64, 2},
	{"rand-64k", "randrw", "64k", 64, 2},
	{"rand-512k", "randrw", "512k", 64, 2},
}

func FioTest(ctx context.Context, path, dir string, size int64) (FioReport, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	size = max(size, minDiskSize)
	file := filepath.Join(dir, fmt.Sprintf(".cii-fio-%d", os.Getpid()))
	defer os.Remove(file)
	rep := FioReport{}
	for _, j := range fioJobs {
		args := []string{"--name=" + j.name, "--filename=" + file, "--size=" + strconv.FormatInt(size, 10),
			"--rw=" + j.rw, "--bs=" + j.bs, "--iodepth=" + strconv.Itoa(j.depth), "--numjobs=" + strconv.Itoa(j.jobs),
			"--direct=1", "--runtime=" + strconv.Itoa(int(randomDuration.Seconds())), "--time_based", "--group_reporting",
			"--ioengine=" + fioEngine(), "--output-format=json"}
		out, err := exec.CommandContext(ctx, path, args...).Output()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return rep, fmt.Errorf("%s: %s", j.name, bytes.TrimSpace(ee.Stderr))
		}
		if err != nil {
			return rep, err
		}
		res, err := parseFio(out)
		if err != nil {
			return rep, fmt.Errorf("%s: %w", j.name, err)
		}
		rep.Version = res.Version
		for _, job := range res.Jobs {
			rep.Jobs = append(rep.Jobs, FioResult{Job: job.Name,
				ReadMBps: job.Read.BWBytes / 1e6, WriteMBps: job.Write.BWBytes / 1e6,
				ReadIOPS: job.Read.IOPS, WriteIOPS: job.Write.IOPS})
		}
	}
	return rep, nil
}

func parseFio(out []byte) (fioOutput, error) {
	var res fioOutput
	if i := bytes.IndexByte(out, '{'); i > 0 {
		out = out[i:]
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return res, err
	}
	if len(res.Jobs) == 0 {
		return res, errors.New("no jobs in fio output")
	}
	return res, nil
}
