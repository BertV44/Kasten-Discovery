package scan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// writeVerbs are the method names that mutate a cluster through client-go.
// Watch is absent on purpose: it is a read.
var writeVerbs = []string{
	"Create", "Update", "UpdateStatus", "Patch", "Apply", "ApplyStatus",
	"Delete", "DeleteCollection",
}

// TestReaderExposesNoWriteVerb: "KDL never mutates the cluster" is a promise
// made to customers, so it is enforced by the type system rather than by
// review. If Reader ever grows a write method, every caller in the package
// gains the ability to mutate and this test is the thing that says no.
func TestReaderExposesNoWriteVerb(t *testing.T) {
	rt := reflect.TypeOf((*Reader)(nil)).Elem()

	for i := 0; i < rt.NumMethod(); i++ {
		m := rt.Method(i).Name
		for _, verb := range writeVerbs {
			if m == verb || strings.HasPrefix(m, verb) {
				t.Errorf("Reader exposes %q: the collector must be read-only by construction", m)
			}
		}
	}

	// Positive control: the interface must still expose the reads it needs, or
	// the check above would pass on an empty interface.
	for _, want := range []string{"List", "Get"} {
		if _, ok := rt.MethodByName(want); !ok {
			t.Errorf("Reader is missing %q; this test would then pass vacuously", want)
		}
	}
}

// TestPackageCallsNoWriteVerb parses every file in this package and fails on a
// call to a write method, wherever it comes from.
//
// The interface check above constrains what the package hands out; this
// constrains what it does internally. Without it, a collector could reach past
// Reader by building its own client -- which is exactly the shape a
// well-meaning change to "just patch one annotation" would take.
func TestPackageCallsNoWriteVerb(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing package: %v", err)
	}

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, call := range writeVerbCalls(fset, file) {
				t.Errorf("%s: %s; the collector must never mutate the cluster", path, call)
			}
		}
	}
}

// writeVerbCalls returns every call to a write verb in src, as "Verb@line".
//
// It matches on the method name alone and does not try to identify the
// receiver. An earlier version keyed off the receiver's *identifier spelling*
// ("dyn", "client", "ri", ...), which meant binding the resource interface to a
// local named x defeated it entirely -- and the point of this guard is that a
// collector must not be able to reach past Reader by building its own client.
//
// Matching on the name alone means a standard-library os.Create or a
// strings.Delete would trip it. That is the correct trade: this package deals
// only in cluster reads, so any of these names appearing here deserves a human
// look, and a guard on a customer-facing promise must fail closed.
func writeVerbCalls(fset *token.FileSet, file *ast.File) []string {
	var found []string
	// Every selector expression, not only those in call position: taking the
	// method VALUE (`del := api.Resource(gvr).Delete`) and calling it later is a
	// selector that never appears as a CallExpr.Fun.
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, verb := range writeVerbs {
			if sel.Sel.Name == verb {
				found = append(found, fmt.Sprintf("%s at %s", verb, fset.Position(sel.Pos())))
			}
		}
		return true
	})
	return found
}

// TestWriteVerbDetectorCatchesAnIndirectCall is the positive control for the
// guard above. Without it, a detector that silently regressed to never matching
// would leave the suite green while the promise it protects went unenforced.
//
// The second case is the one the previous detector missed: the resource
// interface bound to an innocuously named local.
func TestWriteVerbDetectorCatchesAnIndirectCall(t *testing.T) {
	const src = `package scan

func direct(c *clusterReader) { c.dyn.Resource(gvr).Delete(ctx, name, opts) }

func indirect(api dynamic.Interface) {
	x := api.Resource(gvr)
	x.Delete(ctx, name, opts)
}

func methodValue(api dynamic.Interface) {
	del := api.Resource(gvr).Delete
	del(ctx, name, opts)
}

func innocent(items []string) int { return len(items) }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the probe: %v", err)
	}

	found := writeVerbCalls(fset, file)
	if len(found) != 3 {
		t.Errorf("detector found %d write references, want 3 (direct, through a local, and a method value): %v",
			len(found), found)
	}
	// Pin the verb, not just the count: three wrong matches would also be three.
	for _, f := range found {
		if !strings.HasPrefix(f, "Delete") {
			t.Errorf("unexpected match %q, want all three to be Delete", f)
		}
	}
}

// TestClusterReaderKeepsItsClientPrivate: the dynamic client does have the
// write verbs. Exporting the field, or returning it from a method, would hand
// them to every caller and make both tests above decorative.
func TestClusterReaderKeepsItsClientPrivate(t *testing.T) {
	rt := reflect.TypeOf(clusterReader{})
	for i := 0; i < rt.NumField(); i++ {
		if f := rt.Field(i); f.IsExported() {
			t.Errorf("clusterReader.%s is exported: it must not be reachable from outside the package", f.Name)
		}
	}
	for i := 0; i < reflect.TypeOf(&clusterReader{}).NumMethod(); i++ {
		m := reflect.TypeOf(&clusterReader{}).Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			if strings.Contains(m.Type.Out(j).String(), "dynamic.Interface") {
				t.Errorf("clusterReader.%s returns the dynamic client, which carries the write verbs", m.Name)
			}
		}
	}
}
