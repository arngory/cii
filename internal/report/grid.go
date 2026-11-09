package report

import (
	"io"
	"strings"
	"unicode/utf8"
)

type gcell struct {
	text  string
	style func(string) string
}

func plain(s string) gcell { return gcell{text: s} }

func writeGrid(w io.Writer, rows [][]gcell) {
	var widths []int
	for _, row := range rows {
		for i, cell := range row {
			if i == len(row)-1 {
				break
			}
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], utf8.RuneCountInString(cell.text))
		}
	}
	var b strings.Builder
	for _, row := range rows {
		for i, cell := range row {
			text := cell.text
			if cell.style != nil {
				text = cell.style(text)
			}
			b.WriteString(text)
			if i < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell.text)+2))
			}
		}
		b.WriteByte('\n')
	}
	io.WriteString(w, b.String())
}
