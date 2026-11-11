package report

import (
	"encoding"
	"encoding/json"
	"path"
	"reflect"
	"strings"
	"time"
)

const SchemaID = "https://github.com/arngory/cii/schema/report.schema.json"

func JSONSchema() ([]byte, error) {
	defs := map[string]any{}
	root := schemaFor(reflect.TypeOf(Report{}), defs)
	doc := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         SchemaID,
		"title":       "cii report",
		"description": "Output of cii --json (schema " + Schema + ")",
		"$defs":       defs,
	}
	for k, v := range root {
		doc[k] = v
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	return append(out, '\n'), err
}

var (
	timeType      = reflect.TypeOf(time.Time{})
	textMarshaler = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

func schemaFor(t reflect.Type, defs map[string]any) map[string]any {
	switch {
	case t == timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case t.Kind() != reflect.Struct && t.Implements(textMarshaler):
		return map[string]any{"type": "string"}
	case reflect.PointerTo(t).Implements(textMarshaler) && t.Kind() == reflect.Struct:
		return map[string]any{"type": "string"}
	}
	switch t.Kind() {
	case reflect.Pointer:
		inner := schemaFor(t.Elem(), defs)
		return map[string]any{"anyOf": []any{inner, map[string]any{"type": "null"}}}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": []any{"array", "null"}, "items": schemaFor(t.Elem(), defs)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaFor(t.Elem(), defs)}
	case reflect.Struct:
		name := t.Name()
		if pkg := path.Base(t.PkgPath()); pkg != "report" {
			name = strings.ToUpper(pkg[:1]) + pkg[1:] + name
		}
		if _, done := defs[name]; !done {
			defs[name] = true
			defs[name] = structSchema(t, defs)
		}
		return map[string]any{"$ref": "#/$defs/" + name}
	}
	return map[string]any{}
}

func structSchema(t reflect.Type, defs map[string]any) map[string]any {
	props := map[string]any{}
	var required []string
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		props[name] = schemaFor(f.Type, defs)
		if !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
