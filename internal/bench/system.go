package bench

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type System struct {
	OS          string  `json:"os"`
	Kernel      string  `json:"kernel,omitempty"`
	Arch        string  `json:"arch"`
	CPUModel    string  `json:"cpu_model,omitempty"`
	CPUs        int     `json:"cpus"`
	AESNI       bool    `json:"aes_ni"`
	VMX         bool    `json:"vmx"`
	MemTotal    uint64  `json:"mem_total_bytes,omitempty"`
	MemFree     uint64  `json:"mem_available_bytes,omitempty"`
	SwapTotal   uint64  `json:"swap_total_bytes,omitempty"`
	SwapFree    uint64  `json:"swap_free_bytes,omitempty"`
	Virt        string  `json:"virtualization,omitempty"`
	Uptime      float64 `json:"uptime_seconds,omitempty"`
	Load1       float64 `json:"load1,omitempty"`
	Load5       float64 `json:"load5,omitempty"`
	Load15      float64 `json:"load15,omitempty"`
	Distro      string  `json:"distro,omitempty"`
	ProcRoot    string  `json:"-"`
	SysRoot     string  `json:"-"`
	ReleaseFile string  `json:"-"`
}

func CollectSystem() System {
	return collect(System{ProcRoot: "/proc", SysRoot: "/sys", ReleaseFile: "/etc/os-release"})
}

func collect(s System) System {
	s.OS, s.Arch, s.CPUs = runtime.GOOS, runtime.GOARCH, runtime.NumCPU()
	if runtime.GOOS != "linux" {
		return s
	}
	readCPUInfo(&s)
	readMemInfo(&s)
	readUptimeLoad(&s)
	s.Kernel = firstLineField(s.ProcRoot+"/sys/kernel/osrelease", 0)
	s.Distro = osRelease(s.ReleaseFile)
	s.Virt = detectVirt(s)
	return s
}

func readCPUInfo(s *System) {
	f, err := os.Open(s.ProcRoot + "/cpuinfo")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "model name", "Hardware", "Processor":
			if s.CPUModel == "" {
				s.CPUModel = val
			}
		case "flags", "Features":
			flags := " " + val + " "
			s.AESNI = s.AESNI || strings.Contains(flags, " aes ") || strings.Contains(flags, " aes_ni ")
			s.VMX = s.VMX || strings.Contains(flags, " vmx ") || strings.Contains(flags, " svm ")
		}
	}
}

func readMemInfo(s *System) {
	f, err := os.Open(s.ProcRoot + "/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			continue
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			s.MemTotal = kb << 10
		case "MemAvailable":
			s.MemFree = kb << 10
		case "SwapTotal":
			s.SwapTotal = kb << 10
		case "SwapFree":
			s.SwapFree = kb << 10
		}
	}
}

func readUptimeLoad(s *System) {
	if up := firstLineField(s.ProcRoot+"/uptime", 0); up != "" {
		s.Uptime, _ = strconv.ParseFloat(up, 64)
	}
	if b, err := os.ReadFile(s.ProcRoot + "/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
			s.Load5, _ = strconv.ParseFloat(f[1], 64)
			s.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
}

func firstLineField(path string, i int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if i < len(f) {
		return f[i]
	}
	return ""
}

func osRelease(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func detectVirt(s System) string {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	if read(s.SysRoot+"/hypervisor/type") != "" {
		return "xen"
	}
	product := strings.ToLower(read(s.SysRoot+"/class/dmi/id/product_name") + " " + read(s.SysRoot+"/class/dmi/id/sys_vendor") + " " + read(s.SysRoot+"/class/dmi/id/board_vendor"))
	switch {
	case strings.Contains(product, "kvm"), strings.Contains(product, "qemu"):
		return "kvm"
	case strings.Contains(product, "vmware"):
		return "vmware"
	case strings.Contains(product, "virtualbox"):
		return "virtualbox"
	case strings.Contains(product, "microsoft") && strings.Contains(product, "virtual"):
		return "hyper-v"
	case strings.Contains(product, "xen"):
		return "xen"
	case strings.Contains(product, "google"):
		return "gce"
	case strings.Contains(product, "amazon"), strings.Contains(product, "ec2"):
		return "ec2"
	case strings.Contains(product, "openstack"):
		return "openstack"
	case strings.Contains(product, "parallels"):
		return "parallels"
	case strings.Contains(product, "bhyve"):
		return "bhyve"
	}
	if cg := read(s.ProcRoot + "/1/cgroup"); strings.Contains(cg, "docker") || strings.Contains(cg, "lxc") || strings.Contains(cg, "kubepods") {
		return "container"
	}
	if read(s.ProcRoot+"/user_beancounters") != "" {
		return "openvz"
	}
	if _, err := os.Stat(s.ProcRoot + "/vz"); err == nil {
		return "openvz"
	}
	if strings.Contains(strings.ToLower(read(s.ProcRoot+"/cpuinfo")), "hypervisor") {
		return "vm"
	}
	return "none"
}

func (s System) UptimeString() string {
	d := time.Duration(s.Uptime) * time.Second
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	if days > 0 {
		return strconv.Itoa(days) + "d " + strconv.Itoa(h) + "h"
	}
	return strconv.Itoa(h) + "h " + strconv.Itoa(m) + "m"
}
