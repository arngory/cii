package report

import (
	"fmt"
	"io"
	"strconv"

	"github.com/arngory/cii/internal/bench"
)

func (r *Report) SetBench(b *bench.Report) { r.Bench = b }

const benchLabel = 8

func writeBenchCompact(w io.Writer, c paint, m marks, width int, b *bench.Report) {
	line := func(label string, parts []gcell) {
		if len(parts) > 0 {
			writeLine(w, width, m.sep, c.bold(pad(label, benchLabel)), benchLabel, parts)
		}
	}
	line("System", systemParts(b.System))
	if b.Disk != nil {
		line("Disk", diskParts(c, b.Disk))
	}
	if b.Fio != nil {
		line("fio", fioParts(b.Fio))
	}
	if b.CPU != nil {
		line("CPU", cpuParts(b.CPU))
	}
	if b.Speed != nil {
		line("Speed", speedParts(m, b.Speed))
	}
	if len(b.Iperf) > 0 {
		line("iperf3", iperfParts(c, m, b.Iperf))
	}
	for _, n := range b.Notes {
		line("", []gcell{{text: n, style: c.dim}})
	}
}

func systemParts(s bench.System) []gcell {
	var parts []gcell
	add := func(s string) {
		if s != "" {
			parts = append(parts, plain(s))
		}
	}
	add(s.Distro)
	if s.Kernel != "" {
		add(s.OS + " " + s.Kernel)
	} else {
		add(s.OS)
	}
	add(s.Arch)
	cpu := strconv.Itoa(s.CPUs) + " × " + firstNonEmpty(s.CPUModel, "CPU")
	if s.AESNI {
		cpu += ", AES-NI"
	}
	if s.VMX {
		cpu += ", VT-x/AMD-V"
	}
	add(cpu)
	if s.MemTotal > 0 {
		add(fmtBytes(s.MemTotal) + " RAM, " + fmtBytes(s.MemFree) + " free")
	}
	if s.SwapTotal > 0 {
		add("swap " + fmtBytes(s.SwapTotal))
	}
	if s.Virt != "" && s.Virt != "none" {
		add("virt " + s.Virt)
	}
	if s.Uptime > 0 {
		add("up " + s.UptimeString())
	}
	if s.Load1 > 0 || s.Load5 > 0 {
		add(fmt.Sprintf("load %.2f %.2f %.2f", s.Load1, s.Load5, s.Load15))
	}
	return parts
}

func diskParts(c paint, d *bench.DiskReport) []gcell {
	mode := "buffered"
	if d.Direct {
		mode = "direct I/O"
	}
	parts := []gcell{{text: d.Path + ", " + mode + ", " + fmtBytes(uint64(d.SizeBytes)), style: c.dim}}
	parts = append(parts, plain("seq "+fmtMBps(d.Sequential.ReadMBps)+" R / "+fmtMBps(d.Sequential.WriteMBps)+" W"))
	for _, r := range d.Random {
		parts = append(parts, plain(r.Block+" "+fmtMBps(r.ReadMBps)+" / "+fmtMBps(r.WriteMBps)+" ("+fmtIOPS(r.ReadIOPS)+" / "+fmtIOPS(r.WriteIOPS)+" IOPS)"))
	}
	return parts
}

func fioParts(f *bench.FioReport) []gcell {
	parts := []gcell{plain(f.Version)}
	for _, j := range f.Jobs {
		parts = append(parts, plain(j.Job+" "+fmtMBps(j.ReadMBps)+" / "+fmtMBps(j.WriteMBps)+" ("+fmtIOPS(j.ReadIOPS)+" / "+fmtIOPS(j.WriteIOPS)+" IOPS)"))
	}
	return parts
}

func cpuParts(r *bench.CPUReport) []gcell {
	parts := []gcell{plain(fmt.Sprintf("single %.0f", r.Single.Score))}
	if r.Threads > 1 {
		parts = append(parts, plain(fmt.Sprintf("multi %.0f (%d threads)", r.Multi.Score, r.Threads)))
	}
	return append(parts,
		plain("sha256 "+fmtMBps(r.Single.SHA256MBps)),
		plain("aes-gcm "+fmtMBps(r.Single.AESGCMMBps)),
		plain("deflate "+fmtMBps(r.Single.DeflateMBps)))
}

func speedParts(m marks, s *bench.Speed) []gcell {
	server := "Cloudflare"
	if s.Colo != "" {
		server += " " + s.Colo
	}
	return []gcell{plain(server), plain(fmtMs(s.LatencyMs)), plain(m.down + " " + fmtMbps(s.DownMbps)), plain(m.up + " " + fmtMbps(s.UpMbps))}
}

func iperfParts(c paint, m marks, runs []bench.IperfRun) []gcell {
	parts := make([]gcell, 0, len(runs))
	for _, r := range runs {
		name := r.Server.Provider + " " + r.Server.Location
		if r.Client != "cii" {
			name = "[" + r.Client + "] " + name
		}
		if r.Error != "" {
			parts = append(parts, gcell{text: name + ": " + r.Error, style: c.dim})
			continue
		}
		text := name + " " + m.up + " " + fmtMbps(r.SendMbps) + " " + m.down + " " + fmtMbps(r.RecvMbps)
		if r.LatencyMs > 0 {
			text += " " + fmtMs(r.LatencyMs)
		}
		parts = append(parts, plain(text))
	}
	return parts
}

func writeBenchDetailed(w io.Writer, c paint, b *bench.Report) {
	fmt.Fprintln(w, c.bold("System"))
	for _, p := range systemParts(b.System) {
		fmt.Fprintf(w, "  %s\n", p.text)
	}
	fmt.Fprintln(w)
	if b.Disk != nil {
		d := b.Disk
		rows := [][]gcell{{{text: "Disk", style: c.bold}, {text: "read", style: c.bold}, {text: "write", style: c.bold}, {text: "read IOPS", style: c.bold}, {text: "write IOPS", style: c.bold}}}
		rows = append(rows, []gcell{plain("  " + d.Sequential.Block), plain(fmtMBps(d.Sequential.ReadMBps)), plain(fmtMBps(d.Sequential.WriteMBps)), plain(""), plain("")})
		for _, r := range d.Random {
			rows = append(rows, []gcell{plain("  " + r.Block + " random"), plain(fmtMBps(r.ReadMBps)), plain(fmtMBps(r.WriteMBps)), plain(fmtIOPS(r.ReadIOPS)), plain(fmtIOPS(r.WriteIOPS))})
		}
		writeGrid(w, rows)
		fmt.Fprintf(w, "  %s\n\n", c.dim(diskParts(c, d)[0].text))
	}
	if b.Fio != nil {
		rows := [][]gcell{{{text: "fio " + b.Fio.Version, style: c.bold}, {text: "read", style: c.bold}, {text: "write", style: c.bold}, {text: "read IOPS", style: c.bold}, {text: "write IOPS", style: c.bold}}}
		for _, j := range b.Fio.Jobs {
			rows = append(rows, []gcell{plain("  " + j.Job), plain(fmtMBps(j.ReadMBps)), plain(fmtMBps(j.WriteMBps)), plain(fmtIOPS(j.ReadIOPS)), plain(fmtIOPS(j.WriteIOPS))})
		}
		writeGrid(w, rows)
		fmt.Fprintln(w)
	}
	if b.CPU != nil {
		r := b.CPU
		rows := [][]gcell{{{text: "CPU", style: c.bold}, {text: "sha256", style: c.bold}, {text: "aes-gcm", style: c.bold}, {text: "deflate", style: c.bold}, {text: "score", style: c.bold}}}
		score := func(label string, s bench.CPUScore) []gcell {
			return []gcell{plain("  " + label), plain(fmtMBps(s.SHA256MBps)), plain(fmtMBps(s.AESGCMMBps)), plain(fmtMBps(s.DeflateMBps)), plain(fmt.Sprintf("%.0f", s.Score))}
		}
		rows = append(rows, score("single thread", r.Single))
		if r.Threads > 1 {
			rows = append(rows, score(strconv.Itoa(r.Threads)+" threads", r.Multi))
		}
		writeGrid(w, rows)
		fmt.Fprintln(w)
	}
	if b.Speed != nil || len(b.Iperf) > 0 {
		rows := [][]gcell{{{text: "Network", style: c.bold}, {text: "latency", style: c.bold}, {text: "send", style: c.bold}, {text: "receive", style: c.bold}, {text: "", style: c.bold}}}
		if s := b.Speed; s != nil {
			rows = append(rows, []gcell{plain("  Cloudflare " + s.Colo), plain(fmtMs(s.LatencyMs)), plain(fmtMbps(s.UpMbps)), plain(fmtMbps(s.DownMbps)), gcell{text: fmt.Sprintf("%s down, %s up in %.0fs", fmtBytes(uint64(s.DownBytes)), fmtBytes(uint64(s.UpBytes)), s.DurationSec), style: c.dim}})
		}
		for _, r := range b.Iperf {
			name := "  " + r.Server.Provider + " " + r.Server.Location
			if r.Client != "cii" {
				name += " [" + r.Client + "]"
			}
			if r.Error != "" {
				rows = append(rows, []gcell{plain(name), plain("—"), plain("—"), plain("—"), gcell{text: r.Error, style: c.dim}})
				continue
			}
			rows = append(rows, []gcell{plain(name), plain(fmtMs(r.LatencyMs)), plain(fmtMbps(r.SendMbps)), plain(fmtMbps(r.RecvMbps)), gcell{text: r.Server.Host + ":" + strconv.Itoa(r.Port) + ", " + strconv.Itoa(r.Streams) + " streams", style: c.dim}})
		}
		writeGrid(w, rows)
		fmt.Fprintln(w)
	}
	if len(b.Notes) > 0 {
		fmt.Fprintln(w, c.bold("Notes"))
		for _, n := range b.Notes {
			fmt.Fprintf(w, "  %s\n", n)
		}
		fmt.Fprintln(w)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.1f TiB", float64(b)/(1<<40))
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%.0f KiB", float64(b)/(1<<10))
}

func fmtMBps(v float64) string {
	if v >= 1000 {
		return fmt.Sprintf("%.2f GB/s", v/1000)
	}
	return fmt.Sprintf("%.0f MB/s", v)
}

func fmtMbps(v float64) string {
	switch {
	case v >= 1000:
		return fmt.Sprintf("%.2f Gbit/s", v/1000)
	case v >= 100:
		return fmt.Sprintf("%.0f Mbit/s", v)
	}
	return fmt.Sprintf("%.1f Mbit/s", v)
}

func fmtIOPS(v float64) string {
	if v >= 10000 {
		return fmt.Sprintf("%.0fk", v/1000)
	}
	if v >= 1000 {
		return fmt.Sprintf("%.1fk", v/1000)
	}
	return fmt.Sprintf("%.0f", v)
}

func fmtMs(v float64) string {
	if v >= 100 {
		return fmt.Sprintf("%.0f ms", v)
	}
	return fmt.Sprintf("%.1f ms", v)
}
