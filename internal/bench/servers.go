package bench

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var globalServers = []IperfServer{
	{Host: "lon.speedtest.clouvider.net", Ports: "5200-5209", Provider: "Clouvider", Location: "London, UK", IPv6: true},
	{Host: "iperf-ams-nl.eranium.net", Ports: "5201-5210", Provider: "Eranium", Location: "Amsterdam, NL", IPv6: true},
	{Host: "speedtest.uztelecom.uz", Ports: "5200-5209", Provider: "Uztelecom", Location: "Tashkent, UZ", IPv6: true},
	{Host: "speedtest.sin1.sg.leaseweb.net", Ports: "5201-5210", Provider: "Leaseweb", Location: "Singapore, SG", IPv6: true},
	{Host: "la.speedtest.clouvider.net", Ports: "5200-5209", Provider: "Clouvider", Location: "Los Angeles, US", IPv6: true},
	{Host: "speedtest.nyc1.us.leaseweb.net", Ports: "5201-5210", Provider: "Leaseweb", Location: "New York, US", IPv6: true},
}

var ruServers = []IperfServer{
	{Host: "spd-rudp.hostkey.ru", Ports: "5201", Provider: "Hostkey", Location: "Moscow, RU"},
	{Host: "st.spb.ertelecom.ru", Ports: "5202-5209", Provider: "Ertelecom", Location: "Saint Petersburg, RU"},
	{Host: "st.nn.ertelecom.ru", Ports: "5201-5209", Provider: "Ertelecom", Location: "Nizhny Novgorod, RU"},
	{Host: "st.kzn.ertelecom.ru", Ports: "5201-5209", Provider: "Ertelecom", Location: "Kazan, RU"},
	{Host: "st.rostov.ertelecom.ru", Ports: "5201-5209", Provider: "Ertelecom", Location: "Rostov-on-Don, RU"},
	{Host: "st.ekat.ertelecom.ru", Ports: "5201-5209", Provider: "Ertelecom", Location: "Yekaterinburg, RU"},
	{Host: "st.nsk.ertelecom.ru", Ports: "5201-5209", Provider: "Ertelecom", Location: "Novosibirsk, RU"},
	{Host: "st.irkutsk.ertelecom.ru", Ports: "5201-5209", Provider: "Ertelecom", Location: "Irkutsk, RU"},
}

func serversFor(list string) ([]IperfServer, error) {
	var out []IperfServer
	seen := map[string]bool{}
	add := func(servers ...IperfServer) {
		for _, s := range servers {
			if key := s.Host + " " + s.Ports; !seen[key] {
				seen[key] = true
				out = append(out, s)
			}
		}
	}
	if strings.TrimSpace(list) == "" {
		list = "global"
	}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		switch strings.ToLower(entry) {
		case "":
		case "global":
			add(globalServers...)
		case "ru":
			add(ruServers...)
		case "all":
			add(globalServers...)
			add(ruServers...)
		default:
			s, err := parseServer(entry)
			if err != nil {
				return nil, err
			}
			add(s)
		}
	}
	return out, nil
}

func parseServer(spec string) (IperfServer, error) {
	host, rest, ok := strings.Cut(spec, ":")
	if strings.HasPrefix(spec, "[") {
		host, rest, ok = strings.Cut(spec[1:], "]:")
	}
	if !ok || host == "" {
		return IperfServer{}, fmt.Errorf("bad server %q: expected host:ports[:provider[:location]]", spec)
	}
	f := strings.SplitN(rest, ":", 3)
	if _, _, err := portRange(f[0]); err != nil {
		return IperfServer{}, fmt.Errorf("bad server %q: %w", spec, err)
	}
	s := IperfServer{Host: host, Ports: f[0], Provider: "custom", Location: host, IPv6: true}
	if len(f) >= 2 && f[1] != "" {
		s.Provider = f[1]
	}
	if len(f) == 3 && f[2] != "" {
		s.Location = f[2]
	}
	return s, nil
}

func lookTool(tool string) (string, error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return "", errors.New(tool + " is not installed; " + InstallHint(tool))
	}
	return path, nil
}

func InstallHint(tool string) string {
	return installHint(tool, runtime.GOOS, readOSRelease())
}

func readOSRelease() string {
	b, _ := os.ReadFile("/etc/os-release")
	return string(b)
}

func installHint(tool, goos, osRelease string) string {
	switch goos {
	case "darwin":
		return "brew install " + tool
	case "windows":
		return "winget install " + tool
	case "freebsd":
		return "pkg install " + tool
	}
	id := strings.ToLower(osRelease)
	switch {
	case strings.Contains(id, "alpine"):
		return "apk add " + tool
	case strings.Contains(id, "openwrt"):
		return "opkg install " + tool
	case strings.Contains(id, "id=arch"), strings.Contains(id, "id_like=arch"):
		return "pacman -S " + tool
	case strings.Contains(id, "fedora"), strings.Contains(id, "rhel"), strings.Contains(id, "centos"), strings.Contains(id, "rocky"), strings.Contains(id, "alma"):
		return "dnf install " + tool
	case strings.Contains(id, "debian"), strings.Contains(id, "ubuntu"):
		return "apt install " + tool
	case strings.Contains(id, "opensuse"), strings.Contains(id, "suse"):
		return "zypper install " + tool
	}
	return "install " + tool + " with your package manager"
}
