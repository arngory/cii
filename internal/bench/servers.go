package bench

import (
	"errors"
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

var serverSets = map[string][]IperfServer{"global": globalServers, "ru": ruServers}

func ServerSets() []string { return []string{"global", "ru", "all"} }

func serversFor(set string) []IperfServer {
	var out []IperfServer
	for _, entry := range strings.Split(set, ",") {
		entry = strings.TrimSpace(entry)
		switch key := strings.ToLower(entry); key {
		case "":
			out = append(out, globalServers...)
		case "all":
			out = append(out, globalServers...)
			out = append(out, ruServers...)
		case "global", "ru":
			out = append(out, serverSets[key]...)
		default:
			if s, ok := parseServer(entry); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseServer(spec string) (IperfServer, bool) {
	f := strings.Split(spec, ":")
	if len(f) < 2 || f[0] == "" {
		return IperfServer{}, false
	}
	if _, _, err := portRange(f[1]); err != nil {
		return IperfServer{}, false
	}
	s := IperfServer{Host: f[0], Ports: f[1], Provider: "custom", Location: f[0]}
	if len(f) >= 3 && f[2] != "" {
		s.Provider = f[2]
	}
	if len(f) >= 4 && f[3] != "" {
		s.Location = f[3]
	}
	return s, true
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
