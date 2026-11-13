package report

import (
	"html"
	"io"
	"strings"
)

const htmlHead = `<!doctype html>
<html lang="%LANG%">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>%TITLE%</title>
<style>
body{margin:0;background:#0d1117;color:#e6edf3}
pre{margin:0;padding:16px;overflow-x:auto;font:14px/18px 'JetBrains Mono','DejaVu Sans Mono',Menlo,Consolas,monospace;font-variant-ligatures:none}
.b{font-weight:bold}
.d{opacity:.6}
</style>
</head>
<body>
<pre>`

func WriteHTML(w io.Writer, title, lang string, lines []string) error {
	var b strings.Builder
	b.WriteString(strings.NewReplacer("%LANG%", html.EscapeString(lang), "%TITLE%", html.EscapeString(title)).Replace(htmlHead))
	for _, l := range lines {
		for _, r := range svgRuns(l) {
			var classes, styles []string
			if r.st.bold {
				classes = append(classes, "b")
			}
			if r.st.dim {
				classes = append(classes, "d")
			}
			if r.st.fg != "" {
				styles = append(styles, "color:"+r.st.fg)
			}
			if r.st.bg != "" {
				styles = append(styles, "background:"+r.st.bg)
			}
			text := html.EscapeString(r.text)
			if len(classes) == 0 && len(styles) == 0 {
				b.WriteString(text)
				continue
			}
			b.WriteString("<span")
			if len(classes) > 0 {
				b.WriteString(` class="` + strings.Join(classes, " ") + `"`)
			}
			if len(styles) > 0 {
				b.WriteString(` style="` + strings.Join(styles, ";") + `"`)
			}
			b.WriteString(">" + text + "</span>")
		}
		b.WriteString("\n")
	}
	b.WriteString("</pre>\n</body>\n</html>\n")
	_, err := io.WriteString(w, b.String())
	return err
}
