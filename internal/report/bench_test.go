package report

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/arngory/cii/internal/bench"
)

func sampleBench() *bench.Report {
	return &bench.Report{
		System: bench.System{OS: "linux", Kernel: "6.1.0", Arch: "amd64", Distro: "Test Linux 1", CPUs: 4, CPUModel: "Test CPU", AESNI: true,
			MemTotal: 8 << 30, MemFree: 6 << 30, SwapTotal: 1 << 30, Virt: "kvm", Uptime: 90061, Load1: 0.5},
		Disk: &bench.DiskReport{Path: "/tmp", Direct: true, SizeBytes: 1 << 30,
			Sequential: bench.DiskResult{Block: "1m sequential", ReadMBps: 1500, WriteMBps: 900},
			Random:     []bench.DiskResult{{Block: "4k", ReadMBps: 40, WriteMBps: 38, ReadIOPS: 10240, WriteIOPS: 9728}}},
		Fio: &bench.FioReport{Version: "fio-3.33", Jobs: []bench.FioResult{{Job: "rand-4k", ReadMBps: 100, WriteMBps: 50, ReadIOPS: 25600, WriteIOPS: 12800}}},
		CPU: &bench.CPUReport{Threads: 4, Single: bench.CPUScore{SHA256MBps: 400, AESGCMMBps: 2500, DeflateMBps: 60, Score: 314}, Multi: bench.CPUScore{Score: 1200}},
		Speed: &bench.Speed{Server: "speed.cloudflare.com", Colo: "FRA", LatencyMs: 12.34, DownMbps: 940, UpMbps: 87.5,
			DownBytes: 500 << 20, UpBytes: 50 << 20, DurationSec: 10},
		Iperf: []bench.IperfRun{
			{Server: bench.IperfServer{Host: "a.example", Provider: "Prov", Location: "City"}, Client: "cii", Port: 5201, LatencyMs: 150, SendMbps: 1200, RecvMbps: 95.5, Streams: 4},
			{Server: bench.IperfServer{Host: "a.example", Provider: "Prov", Location: "City"}, Client: "iperf3", Port: 5202, SendMbps: 800, RecvMbps: 700, Streams: 4},
			{Server: bench.IperfServer{Host: "b.example", Provider: "Other", Location: "Town"}, Client: "cii", Streams: 4, Error: "server busy"},
		},
		Notes: []string{"fio is not installed; apt install fio"},
	}
}

func TestBenchCompact(t *testing.T) {
	r := &Report{Bench: sampleBench()}
	for _, st := range []Style{{Unicode: true, Width: 100}, {Width: 60}} {
		var b strings.Builder
		r.WriteCompact(&b, st, nil)
		out := b.String()
		want := []string{
			"System", "Test Linux 1", "linux 6.1.0", "4 × Test CPU, AES-NI", "8.0 GiB RAM, 6.0 GiB free", "swap 1.0 GiB", "virt kvm", "up 1d 1h", "load 0.50",
			"Disk", "/tmp, direct I/O, 1.0 GiB", "seq 1.50 GB/s R / 900 MB/s W", "4k 40 MB/s / 38 MB/s (10k / 9.7k IOPS)",
			"fio", "fio-3.33", "rand-4k 100 MB/s / 50 MB/s (26k / 13k IOPS)",
			"CPU", "single 314", "multi 1200 (4 threads)", "aes-gcm 2.50 GB/s",
			"Speed", "Cloudflare FRA", "12.3 ms", "940 Mbit/s", "87.5 Mbit/s",
			"iperf3", "1.20 Gbit/s", "95.5 Mbit/s", "150 ms", "[iperf3] Prov City", "Other Town: server busy",
			"fio is not installed; apt install fio",
		}
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("width %d: %q missing in\n%s", st.Width, w, out)
			}
		}
		arrow := "↓ 940"
		if !st.Unicode {
			arrow = "down 940"
		}
		if !strings.Contains(out, arrow) {
			t.Errorf("width %d: %q missing in\n%s", st.Width, arrow, out)
		}
		for _, line := range strings.Split(out, "\n") {
			if utf8.RuneCountInString(line) > st.Width {
				t.Errorf("width %d: line too long: %q", st.Width, line)
			}
		}
	}
}

func TestSetBenchMasksErrors(t *testing.T) {
	note := "cloudflare: read tcp 203.0.113.5:40000->104.16.1.1:443: i/o timeout"
	fail := "connect: dial tcp 203.0.113.5:0->198.51.100.7:5201: connect: connection refused"
	for _, mask := range []bool{false, true} {
		b := sampleBench()
		b.Notes = append(b.Notes, note)
		b.Iperf[2].Error = fail
		r := New("bench", mask)
		r.SetBench(b, mask)
		got := strings.Join(r.Bench.Notes, "\n") + "\n" + r.Bench.Iperf[2].Error
		if leaked := strings.Contains(got, "203.0.113.5"); leaked == mask {
			t.Errorf("mask=%v: %q", mask, got)
		}
		if mask && (!strings.Contains(got, "203.0.*.*") || !strings.Contains(got, "fio is not installed; apt install fio")) {
			t.Errorf("masked text = %q", got)
		}
	}
}

func TestBenchDetailed(t *testing.T) {
	r := &Report{Bench: sampleBench()}
	var b strings.Builder
	r.WriteDetailed(&b, false)
	out := b.String()
	for _, w := range []string{
		"System", "Disk", "1m sequential", "4k random", "fio fio-3.33", "single thread", "4 threads", "Network",
		"Cloudflare FRA", "500 MiB down, 50 MiB up in 10s", "Prov City [iperf3]", "a.example:5201, 4 streams", "server busy", "Notes",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("%q missing in\n%s", w, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour codes in plain output")
	}
}
