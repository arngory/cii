package bench

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
)

func noEnvProxy(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		t.Setenv(k, "")
	}
}

func testNet(t *testing.T, hosts ...string) (*netx.Net, *ledger.Ledger) {
	t.Helper()
	noEnvProxy(t)
	var rules []netx.Rule
	for _, h := range hosts {
		rules = append(rules, netx.Rule{Module: Module, Pattern: h, Purpose: "test"})
	}
	led := ledger.New()
	return netx.New(netx.Options{Timeout: 3 * time.Second, Family: netx.IPv4}, netx.NewPolicy(rules...), led), led
}

type fakeIperf struct {
	ln      net.Listener
	busy    bool
	mu      sync.Mutex
	params  []iperfParams
	cookies map[string]int
}

func adjacentListeners(t *testing.T, count int) []net.Listener {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		first, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns := []net.Listener{first}
		base := first.Addr().(*net.TCPAddr).Port
		for i := 1; i < count; i++ {
			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(base+i)))
			if err != nil {
				break
			}
			lns = append(lns, ln)
		}
		if len(lns) == count {
			return lns
		}
		for _, ln := range lns {
			ln.Close()
		}
	}
	t.Fatal("no adjacent free ports")
	return nil
}

func newFakeIperf(t *testing.T, ln net.Listener, busy bool) *fakeIperf {
	t.Helper()
	s := &fakeIperf{ln: ln, busy: busy, cookies: map[string]int{}}
	t.Cleanup(func() { ln.Close() })
	go s.serve()
	return s
}

func (s *fakeIperf) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeIperf) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *fakeIperf) handle(c net.Conn) {
	defer c.Close()
	cookie := make([]byte, cookieSize)
	if _, err := io.ReadFull(c, cookie); err != nil {
		return
	}
	s.mu.Lock()
	s.cookies[string(cookie)]++
	n := s.cookies[string(cookie)]
	s.mu.Unlock()
	if n > 1 {
		s.stream(c)
		return
	}
	if s.busy {
		c.Write([]byte{byte(0xfe)})
		binary.Write(c, binary.BigEndian, [2]int32{10, 0})
		return
	}
	c.Write([]byte{stateParamExchange})
	var p iperfParams
	if err := readJSON(c, &p); err != nil {
		return
	}
	s.mu.Lock()
	s.params = append(s.params, p)
	s.mu.Unlock()
	c.Write([]byte{stateCreateStreams})
	time.Sleep(200 * time.Millisecond)
	c.Write([]byte{stateTestStart, stateTestRunning})
	var b [1]byte
	io.ReadFull(c, b[:])
	c.Write([]byte{stateExchangeResults})
	var client iperfResults
	if err := readJSON(c, &client); err != nil {
		return
	}
	var total int64
	for _, st := range client.Streams {
		total += st.Bytes
	}
	if p.Reverse {
		total = 4 << 20
	}
	writeJSON(c, iperfResults{Streams: []iperfStreamResult{{ID: 1, Bytes: total}}})
	c.Write([]byte{stateDisplayResults})
}

func (s *fakeIperf) stream(c net.Conn) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

func TestIperfAgainstFakeServer(t *testing.T) {
	lns := adjacentListeners(t, 3)
	lns[0].Close()
	busy := newFakeIperf(t, lns[1], true)
	good := newFakeIperf(t, lns[2], false)
	n, _ := testNet(t, "127.0.0.1")
	s := IperfServer{Host: "127.0.0.1", Ports: fmt.Sprintf("%d-%d", busy.port()-1, good.port()), Provider: "p", Location: "l"}
	run := IperfTest(context.Background(), n, s, 300*time.Millisecond)
	if run.Error != "" {
		t.Fatalf("error: %s", run.Error)
	}
	if run.Port != good.port() || run.Client != clientNative || run.SendMbps <= 0 || run.RecvMbps <= 0 || run.LatencyMs <= 0 {
		t.Errorf("run = %+v", run)
	}
	good.mu.Lock()
	defer good.mu.Unlock()
	if len(good.params) != 2 || good.params[0].Reverse || !good.params[1].Reverse || good.params[0].Parallel != iperfStreams || !good.params[0].TCP {
		t.Errorf("params = %+v", good.params)
	}
}

func TestIperfBusyAndPolicy(t *testing.T) {
	busy := newFakeIperf(t, adjacentListeners(t, 1)[0], true)
	n, led := testNet(t, "127.0.0.1")
	s := IperfServer{Host: "127.0.0.1", Ports: strconv.Itoa(busy.port())}
	if run := IperfTest(context.Background(), n, s, 200*time.Millisecond); run.Error != errBusy.Error() {
		t.Errorf("busy run = %+v", run)
	}
	if run := IperfTest(context.Background(), n, IperfServer{Host: "127.0.0.2", Ports: "5201"}, 200*time.Millisecond); !strings.Contains(run.Error, "not allowed") {
		t.Errorf("undeclared host run = %+v", run)
	}
	v6, _ := netx.New(netx.Options{Timeout: time.Second, Family: netx.IPv6}, netx.NewPolicy(), ledger.New()), 0
	if run := IperfTest(context.Background(), v6, IperfServer{Host: "x", Ports: "1"}, time.Second); run.Error != "no IPv6 endpoint" {
		t.Errorf("v6 run = %+v", run)
	}
	blocked := 0
	for _, e := range led.Entries() {
		blocked += e.Blocked
	}
	if blocked != 1 {
		t.Errorf("blocked = %d", blocked)
	}
}

func TestIperfProxied(t *testing.T) {
	noEnvProxy(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	led := ledger.New()
	n := netx.New(netx.Options{Timeout: time.Second, Family: netx.IPv4}, netx.NewPolicy(netx.Rule{Module: Module, Pattern: "127.0.0.1"}), led)
	rep := Run(context.Background(), Env{Net: n, Ledger: led}, Options{Iperf: true, Servers: "127.0.0.1:1"}, nil)
	if len(rep.Iperf) != 0 || len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "proxy") {
		t.Errorf("report = %+v", rep)
	}
}

func TestCookieAndPorts(t *testing.T) {
	c := makeCookie()
	if len(c) != cookieSize || c[cookieSize-1] != 0 {
		t.Fatalf("cookie %q", c)
	}
	for _, b := range c[:cookieSize-1] {
		if !strings.ContainsRune(cookieAlphabet, rune(b)) {
			t.Errorf("byte %q outside alphabet", b)
		}
	}
	for spec, want := range map[string][2]int{"5201": {5201, 5201}, "5200-5209": {5200, 5209}} {
		lo, hi, err := portRange(spec)
		if err != nil || lo != want[0] || hi != want[1] {
			t.Errorf("portRange(%q) = %d %d %v", spec, lo, hi, err)
		}
	}
	for _, bad := range []string{"", "x", "5210-5201", "1-", "0", "70000", "1-99999999", "-5201", "5201-5202-5203"} {
		if _, _, err := portRange(bad); err == nil {
			t.Errorf("portRange(%q) accepted", bad)
		}
	}
}

func TestServerSets(t *testing.T) {
	all, err := serversFor("all, ru, global")
	if err != nil || len(all) != len(globalServers)+len(ruServers) {
		t.Errorf("all = %d %v", len(all), err)
	}
	for _, list := range []string{"", " ", "global", "global,"} {
		if got, err := serversFor(list); err != nil || len(got) != len(globalServers) {
			t.Errorf("serversFor(%q) = %d %v", list, len(got), err)
		}
	}
	got, err := serversFor("RU, host.example:5201-5205:Prov:Place, [2001:db8::1]:5201, host.example:5201-5205")
	if err != nil || len(got) != len(ruServers)+2 {
		t.Fatalf("mixed = %+v %v", got, err)
	}
	custom := got[len(ruServers)]
	if custom.Host != "host.example" || custom.Ports != "5201-5205" || custom.Provider != "Prov" || custom.Location != "Place" || !custom.IPv6 {
		t.Errorf("custom = %+v", custom)
	}
	literal := got[len(ruServers)+1]
	if literal.Host != "2001:db8::1" || literal.Ports != "5201" || literal.Provider != "custom" || literal.Location != "2001:db8::1" || !literal.IPv6 {
		t.Errorf("literal = %+v", literal)
	}
	for _, bad := range []string{"global,myhost", "nohost:x", ":5201", "host.example:0", "host.example:70000", "[2001:db8::1]", "[]:5201"} {
		if got, err := serversFor(bad); err == nil {
			t.Errorf("serversFor(%q) = %+v", bad, got)
		}
		if err := (Options{Duration: time.Second, Servers: bad}).Validate(); err == nil || !strings.Contains(err.Error(), "--servers") {
			t.Errorf("Validate(%q) = %v", bad, err)
		}
	}
	for dur, ok := range map[time.Duration]bool{time.Second: true, time.Minute: true, 300 * time.Millisecond: false, 1500 * time.Millisecond: false, 2 * time.Minute: false, 0: false} {
		if err := (Options{Duration: dur}).Validate(); (err == nil) != ok {
			t.Errorf("Validate(%s) = %v", dur, err)
		}
	}
	seen := map[string]bool{}
	for _, s := range all {
		if seen[s.Host] {
			t.Errorf("duplicate host %s", s.Host)
		}
		seen[s.Host] = true
		if _, _, err := portRange(s.Ports); err != nil || s.Provider == "" || s.Location == "" {
			t.Errorf("bad server %+v", s)
		}
	}
	rules := Rules(Options{Net: true, Iperf: true, Servers: "ru"})
	if len(rules) != len(ruServers)+1 || rules[0].Pattern != cloudflareSpeedHost {
		t.Errorf("rules = %+v", rules)
	}
}

func TestInstallHint(t *testing.T) {
	cases := []struct{ goos, release, want string }{
		{"darwin", "", "brew install fio"},
		{"windows", "", "winget install fio"},
		{"linux", "ID=alpine\n", "apk add fio"},
		{"linux", "ID=arch\n", "pacman -S fio"},
		{"linux", "ID=manjaro\nID_LIKE=arch\n", "pacman -S fio"},
		{"linux", "ID=openwrt\n", "opkg install fio"},
		{"linux", "ID=ubuntu\nID_LIKE=debian\n", "apt install fio"},
		{"linux", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", "dnf install fio"},
		{"linux", "ID=opensuse-leap\n", "zypper install fio"},
		{"linux", "", "install fio with your package manager"},
	}
	for _, c := range cases {
		if got := installHint("fio", c.goos, c.release); got != c.want {
			t.Errorf("installHint(%s, %q) = %q, want %q", c.goos, c.release, got, c.want)
		}
	}
}

func TestCloudflareAgainstFakeServer(t *testing.T) {
	var ups int64
	rejections := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cdn-cgi/trace":
			fmt.Fprint(w, "fl=1\nip=1.2.3.4\ncolo=FRA\n")
		case r.URL.Path == "/__down":
			n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
			if n > 2<<20 {
				rejections++
				w.WriteHeader(http.StatusForbidden)
				return
			}
			io.CopyN(w, &zeroReader{n: n}, n)
		case r.URL.Path == "/__up" && r.Method == http.MethodPost:
			n, _ := io.Copy(io.Discard, r.Body)
			ups += n
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s, err := cloudflareSpeed(context.Background(), srv.Client(), srv.URL, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if s.Colo != "FRA" || s.LatencyMs <= 0 || s.DownMbps <= 0 || s.UpMbps <= 0 || s.DownBytes < 3<<20 || s.UpBytes != ups || rejections != 1 {
		t.Errorf("speed = %+v (ups %d, rejections %d)", s, ups, rejections)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer bad.Close()
	if _, err := cloudflareSpeed(context.Background(), bad.Client(), bad.URL, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("403 err = %v", err)
	}
}

func TestDiskSmall(t *testing.T) {
	rep, err := diskTest(context.Background(), t.TempDir(), 4<<20, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if rep.SizeBytes != 4<<20 || rep.Sequential.ReadMBps <= 0 || rep.Sequential.WriteMBps <= 0 || len(rep.Random) != len(blockSizes) {
		t.Fatalf("report = %+v", rep)
	}
	for _, r := range rep.Random {
		if r.ReadIOPS+r.WriteIOPS <= 0 || r.Block == "" {
			t.Errorf("random %+v", r)
		}
	}
	entries, _ := os.ReadDir(rep.Path)
	if len(entries) != 0 {
		t.Errorf("temp file left behind: %v", entries)
	}
	if _, err := diskTest(context.Background(), filepath.Join(t.TempDir(), "missing"), 4<<20, time.Millisecond); err == nil {
		t.Error("missing dir accepted")
	}
}

func TestScratchFileIsExclusive(t *testing.T) {
	dir := t.TempDir()
	a, b := scratchName(dir, "bench"), scratchName(dir, "bench")
	if a == b || filepath.Dir(a) != dir || !strings.HasPrefix(filepath.Base(a), ".cii-bench-") {
		t.Fatalf("scratch names %q %q", a, b)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, _, err := openDirect(victim); err == nil {
		f.Close()
		t.Error("existing file reused")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err == nil {
		if f, _, err := openDirect(link); err == nil {
			f.Close()
			t.Error("symlink followed")
		}
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "keep" {
		t.Errorf("victim = %q %v", got, err)
	}
	f, _, err := openDirect(a)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := os.Stat(a); err != nil {
		t.Error(err)
	}
}

func TestCPUSmall(t *testing.T) {
	rep := cpuTest(context.Background(), 30*time.Millisecond)
	if rep.Single.SHA256MBps <= 0 || rep.Single.AESGCMMBps <= 0 || rep.Single.DeflateMBps <= 0 || rep.Single.Score <= 0 || rep.Threads < 1 {
		t.Errorf("report = %+v", rep)
	}
	text := make([]byte, 1<<16)
	fillText(text, 3)
	var packed bytes.Buffer
	w, _ := flate.NewWriter(&packed, flate.DefaultCompression)
	w.Write(text)
	w.Close()
	if ratio := float64(len(text)) / float64(packed.Len()); ratio < 1.5 || ratio > 6 {
		t.Errorf("workload compresses %.1f times, want text-like", ratio)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rep := cpuTest(ctx, time.Second); rep.Single.Score != 0 {
		t.Errorf("cancelled run scored %+v", rep.Single)
	}
}

func TestSystemFromFixtures(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	write("proc/cpuinfo", "processor\t: 0\nmodel name\t: Test CPU 3000\nflags\t\t: fpu aes vmx hypervisor\n\nprocessor\t: 1\nmodel name\t: Test CPU 3000\n")
	write("proc/meminfo", "MemTotal:        8000000 kB\nMemAvailable:    6000000 kB\nSwapTotal:       1000000 kB\nSwapFree:         500000 kB\n")
	write("proc/uptime", "90061.5 1000.0\n")
	write("proc/loadavg", "0.50 0.25 0.10 1/200 123\n")
	write("proc/sys/kernel/osrelease", "6.1.0-test\n")
	write("sys/class/dmi/id/product_name", "KVM\n")
	write("os-release", "NAME=\"Test\"\nPRETTY_NAME=\"Test Linux 1\"\n")
	s := collect(System{ProcRoot: root + "/proc", SysRoot: root + "/sys", ReleaseFile: root + "/os-release"})
	if s.OS != "linux" {
		t.Skip("fixture parsing is linux-only")
	}
	if s.CPUModel != "Test CPU 3000" || !s.AESNI || !s.VMX || s.MemTotal != 8000000<<10 || s.MemFree != 6000000<<10 ||
		s.SwapTotal != 1000000<<10 || s.Uptime != 90061.5 || s.Load1 != 0.5 || s.Kernel != "6.1.0-test" || s.Distro != "Test Linux 1" || s.Virt != "kvm" {
		t.Errorf("system = %+v", s)
	}
	if got := s.UptimeString(); got != "1d 1h" {
		t.Errorf("uptime = %q", got)
	}
}

func TestSystemIperf3Arguments(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.7")
	got := strings.Join(iperf3Args(netx.Options{Family: netx.IPv4, Source: src}, "h.example", 5203, 10*time.Second, true), " ")
	if got != "-c h.example -p 5203 -P 4 -t 10 -J -4 -B 192.0.2.7 -R" {
		t.Errorf("args = %q", got)
	}
	got = strings.Join(iperf3Args(netx.Options{Family: netx.IPv6}, "h.example", 5201, 300*time.Millisecond, false), " ")
	if got != "-c h.example -p 5201 -P 4 -t 1 -J -6" {
		t.Errorf("args = %q", got)
	}
	if got := iperf3Args(netx.Options{}, "h", 1, time.Second, false); strings.Contains(strings.Join(got, " "), "-4") {
		t.Errorf("any-family args = %q", got)
	}

	if runtime.GOOS == "windows" {
		t.Skip("fake iperf3 is a shell script")
	}
	noEnvProxy(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	tool := filepath.Join(dir, "iperf3")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\necho '{\"end\":{\"sum_sent\":{\"bits_per_second\":8e8},\"sum_received\":{\"bits_per_second\":7e8}}}'\n"
	if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	n := netx.New(netx.Options{Timeout: time.Second, Family: netx.IPv6}, netx.NewPolicy(netx.Rule{Module: Module, Pattern: "::1"}), led)
	env := Env{Net: n, Ledger: led}
	run := SystemIperf3(context.Background(), env, tool, IperfServer{Host: "::1", Ports: "5201", IPv6: true}, 2*time.Second)
	if run.Error != "" || run.SendMbps != 800 || run.RecvMbps != 700 || run.Port != 5201 || run.Client != clientSystem {
		t.Errorf("run = %+v", run)
	}
	calls, _ := os.ReadFile(log)
	if string(calls) != "-c ::1 -p 5201 -P 4 -t 2 -J -6\n-c ::1 -p 5201 -P 4 -t 2 -J -6 -R\n" {
		t.Errorf("calls = %q", calls)
	}
	if run := SystemIperf3(context.Background(), env, tool, IperfServer{Host: "::1", Ports: "5201"}, time.Second); run.Error != "no IPv6 endpoint" {
		t.Errorf("v4-only server run = %+v", run)
	}
	if run := SystemIperf3(context.Background(), env, tool, IperfServer{Host: "undeclared.example", Ports: "5201", IPv6: true}, time.Second); !strings.Contains(run.Error, "not allowed") {
		t.Errorf("undeclared host run = %+v", run)
	}
}

func TestParseExternalOutputs(t *testing.T) {
	var out iperf3Output
	if err := json.Unmarshal([]byte(`{"start":{"connected":[{"remote_port":5201}]},"end":{"sum_sent":{"bits_per_second":9.4e8},"sum_received":{"bits_per_second":9.1e8}}}`), &out); err != nil {
		t.Fatal(err)
	}
	if out.End.SumSent.BitsPerSecond != 9.4e8 || out.End.SumReceived.BitsPerSecond != 9.1e8 {
		t.Errorf("iperf3 = %+v", out)
	}
	fio, err := parseFio([]byte("fio: warning\n{\"fio version\":\"fio-3.33\",\"jobs\":[{\"jobname\":\"rand-4k\",\"read\":{\"bw_bytes\":104857600,\"iops\":25600},\"write\":{\"bw_bytes\":52428800,\"iops\":12800}}]}"))
	if err != nil {
		t.Fatal(err)
	}
	if fio.Version != "fio-3.33" || fio.Jobs[0].Read.IOPS != 25600 || fio.Jobs[0].Write.BWBytes != 52428800 {
		t.Errorf("fio = %+v", fio)
	}
	if _, err := parseFio([]byte(`{"jobs":[]}`)); err == nil {
		t.Error("empty jobs accepted")
	}
}
