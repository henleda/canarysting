package views

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestTraceProjectionStaysOffDecisionAndWritePaths(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "trace.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, prohibited := range []string{
			"/adapters/", "/bpf/", "/contract/", "/engine/", "/intelligence/", "/persist/", "/sting/",
		} {
			if strings.Contains(path, prohibited) {
				t.Fatalf("trace projection imports prohibited path %q", path)
			}
		}
	}

	forbiddenField := func(name string) bool {
		name = strings.ToLower(name)
		return strings.Contains(name, "action") || strings.Contains(name, "verdict") || strings.Contains(name, "tier")
	}
	var inspect func(reflect.Type)
	seen := make(map[reflect.Type]bool)
	inspect = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if forbiddenField(field.Name) || forbiddenField(strings.Split(field.Tag.Get("json"), ",")[0]) {
				t.Fatalf("trace projection exposes decision/write field %s.%s", typ.Name(), field.Name)
			}
			inspect(field.Type)
		}
	}
	inspect(reflect.TypeOf(TraceWorkspace{}))

	// Keep the parser import intentional: a test that no longer traverses the
	// syntax tree should not silently retain an unused parser setup.
	if file.Name == nil || file.Name.Name != "views" || !ast.IsExported("TraceWorkspace") {
		t.Fatal("trace projection source was not parsed as the views package")
	}
}
