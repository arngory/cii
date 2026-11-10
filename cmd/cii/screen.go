package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/arngory/cii/internal/report"
)

const (
	enterScreen = "\x1b[?1049h\x1b[?25l"
	leaveScreen = "\x1b[?25h\x1b[?1049l"
	redrawEvery = 150 * time.Millisecond
)

type liveScreen struct {
	quit chan struct{}
	done chan struct{}
	once sync.Once
}

func liveCapable(c *common) bool {
	fd := int(os.Stdout.Fd())
	return !c.json && !c.debug && term.IsTerminal(fd) && os.Getenv("TERM") != "dumb" && enableVT()
}

func startScreen(c *common, s *session) *liveScreen {
	if !liveCapable(c) {
		return nil
	}
	l := &liveScreen{quit: make(chan struct{}), done: make(chan struct{})}
	started := time.Now()
	os.Stdout.WriteString(enterScreen)
	go func() {
		defer close(l.done)
		tick := time.NewTicker(redrawEvery)
		defer tick.Stop()
		prev := ""
		for {
			if frame := liveFrame(c, s, started); frame != prev {
				os.Stdout.WriteString(frame)
				prev = frame
			}
			select {
			case <-l.quit:
				return
			case <-tick.C:
			}
		}
	}()
	return l
}

func (l *liveScreen) stop() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.quit)
		<-l.done
		os.Stdout.WriteString(leaveScreen)
	})
}

func liveFrame(c *common, s *session, started time.Time) string {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		width = 100
	}
	if err != nil || height <= 2 {
		height = 40
	}
	rep := s.report()
	status := "detecting the public address"
	if done, total := report.Progress(rep); total > 0 {
		status = fmt.Sprintf("checking %d/%d", done, total)
	}
	header := fmt.Sprintf("%s %s · %s · %ds · Ctrl+C stops and shows what is done", rep.Tool.Name, rep.Tool.Version, status, int(time.Since(started).Seconds()))
	lines := rep.Screen(report.Style{Color: c.color(), Unicode: report.UnicodeTerminal(), Width: width}, header, nil)
	if len(lines) > height {
		hidden := len(lines) - height + 1
		lines = append(lines[:height-1], clipRunes(fmt.Sprintf("… %d more lines, the full view is printed when the run ends", hidden), width))
	}
	return "\x1b[H\x1b[K" + strings.Join(lines, "\r\n\x1b[K") + "\x1b[J"
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:max(0, n-1)]) + "…"
	}
	return s
}
