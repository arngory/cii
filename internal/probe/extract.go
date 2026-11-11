package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func JSONPath(path string) func(*Response) string {
	return JSONPathAfter("", path)
}

func JSONPathAfter(prefix, path string) func(*Response) string {
	steps := parsePath(path)
	return func(r *Response) string {
		var v any
		if json.Unmarshal(bytes.TrimPrefix(bytes.TrimSpace(r.Body), []byte(prefix)), &v) != nil {
			return ""
		}
		s, _ := walk(v, steps).(string)
		return s
	}
}

func parsePath(path string) []string {
	var steps []string
	for _, part := range strings.Split(path, ".") {
		for part != "" {
			i := strings.IndexByte(part, '[')
			switch {
			case i < 0:
				steps = append(steps, part)
				part = ""
			case i > 0:
				steps = append(steps, part[:i])
				part = part[i:]
			default:
				j := strings.IndexByte(part, ']')
				if j < 0 {
					return append(steps, "\x00")
				}
				steps = append(steps, part[:j+1])
				part = part[j+1:]
			}
		}
	}
	return steps
}

func walk(v any, steps []string) any {
	for _, s := range steps {
		if idx, ok := strings.CutPrefix(s, "["); ok {
			n, err := strconv.Atoi(strings.TrimSuffix(idx, "]"))
			arr, isArr := v.([]any)
			if err != nil || !isArr || n < 0 || n >= len(arr) {
				return nil
			}
			v = arr[n]
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[s]
	}
	return v
}

func BodyRegex(expr string) func(*Response) string {
	re := regexp.MustCompile(expr)
	return func(r *Response) string {
		if m := re.FindSubmatch(r.Body); m != nil {
			return string(m[1])
		}
		return ""
	}
}

func HeaderRegex(name, expr string) func(*Response) string {
	re := regexp.MustCompile(expr)
	return func(r *Response) string {
		for _, v := range r.Header.Values(name) {
			if m := re.FindStringSubmatch(v); m != nil {
				return m[1]
			}
		}
		return ""
	}
}

func WholeBody(r *Response) string {
	return string(bytes.TrimSpace(r.Body))
}

func CountryFrom(extract func(*Response) string, blockStatus int) func([]*Response) []Result {
	return func(rs []*Response) []Result {
		r := rs[0]
		if blockStatus != 0 && r.Status == blockStatus {
			return []Result{{Status: IPBlock, Reason: fmt.Sprintf("HTTP %d", r.Status)}}
		}
		return []Result{CountryResult(extract(r), r.Status)}
	}
}
