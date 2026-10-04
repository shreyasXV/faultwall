package main

// audit_nohttp_test.go: `faultwall audit` makes no network calls besides the
// one Postgres connection.
//
// The test type-checks this package (go/types, export data from
// `go list -export`) and walks the static call graph from runAudit and every
// init() function. It fails if anything reachable uses net/http (constructs a
// client or request, calls http.Get, ...), net/smtp or net/rpc, or reaches the
// package's own phone-out code (telemetry, control plane, Slack, APA, hold).
//
// tests/e2e/audit/run.sh also runs the real binary under a macOS sandbox that
// denies all outbound network except the database port.

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var auditNetworkPackages = map[string]bool{"net/http": true, "net/smtp": true, "net/rpc": true, "net/http/httptrace": true}

// auditNetworkFuncs are same-package entry points that phone out.
var auditNetworkFuncs = map[string]bool{
	"holdHTTP": true, "NewTelemetryClient": true, "NewSlackNotifier": true,
	"newAPAClient": true, "NewAPAClient": true,
}

func TestAuditMakesNoHTTPCalls(t *testing.T) {
	violations, reached := auditNetworkWalk(t, func(name string, isInit bool) bool { return name == "runAudit" || isInit })
	for _, v := range violations {
		t.Error("network call reachable from faultwall audit: " + v)
	}
	for _, must := range []string{"collectAudit", "gatherAudit", "buildAuditFix", "renderAuditText", "isSecretColumn", "normalizeLibPQSSLMode", "serverSupportsTLS"} {
		if !reached[must] {
			t.Errorf("call-graph walk did not reach %s (the test would be checking nothing)", must)
		}
	}
	if os.Getenv("AUDIT_PRINT_REACHED") != "" {
		var r []string
		for k := range reached {
			r = append(r, k)
		}
		sort.Strings(r)
		t.Log(strings.Join(r, " "))
	}
}

// TestAuditNoHTTPWalkCatchesViolations proves the walker notices a network
// call: walking from runTry (which starts the telemetry client) must trip it.
func TestAuditNoHTTPWalkCatchesViolations(t *testing.T) {
	violations, _ := auditNetworkWalk(t, func(name string, _ bool) bool { return name == "runTry" })
	if len(violations) == 0 {
		t.Fatal("walker found no network use from runTry; the no-HTTP test is blind")
	}
}

func auditNetworkWalk(t *testing.T, isRoot func(name string, isInit bool) bool) (violations []string, reachedNames map[string]bool) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	// export data for every dependency
	out, err := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Export", ".").Output()
	if err != nil {
		t.Fatalf("go list -export: %v", err)
	}
	exports := map[string]string{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p struct{ ImportPath, Export string }
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		exports[p.ImportPath] = p.Export
	}

	fset := token.NewFileSet()
	names, _ := filepath.Glob("*.go")
	var files []*ast.File
	for _, n := range names {
		if ok, _ := build.Default.MatchFile(".", n); strings.HasSuffix(n, "_test.go") || !ok {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		p, ok := exports[path]
		if !ok || p == "" {
			return nil, os.ErrNotExist
		}
		return os.Open(p)
	})
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	conf := types.Config{Importer: imp, Error: func(error) {}}
	pkg, _ := conf.Check("github.com/shreyasXV/faultwall", fset, files, info)
	if pkg == nil {
		t.Fatal("type-check failed")
	}

	// map package-level funcs/methods and vars to their declaration node
	decl := map[types.Object]ast.Node{}
	var roots []types.Object
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				obj := info.Defs[d.Name]
				if obj == nil {
					continue
				}
				decl[obj] = d
				if isRoot(d.Name.Name, d.Name.Name == "init" && d.Recv == nil) {
					roots = append(roots, obj)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if vs, ok := s.(*ast.ValueSpec); ok {
						for _, n := range vs.Names {
							if obj := info.Defs[n]; obj != nil {
								decl[obj] = vs
							}
						}
					}
				}
			}
		}
	}
	if len(roots) == 0 {
		t.Fatal("root function not found")
	}
	seen := map[types.Object]bool{}
	parent := map[types.Object]types.Object{}
	queue := append([]types.Object(nil), roots...)
	for _, r := range roots {
		seen[r] = true
	}
	path := func(o types.Object) string {
		var p []string
		for x := o; x != nil; x = parent[x] {
			p = append([]string{x.Name()}, p...)
		}
		return strings.Join(p, " -> ")
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		node := decl[cur]
		if node == nil {
			continue
		}
		ast.Inspect(node, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			obj := info.Uses[id]
			if obj == nil || obj.Pkg() == nil {
				return true
			}
			if auditNetworkPackages[obj.Pkg().Path()] {
				violations = append(violations, path(cur)+" uses "+obj.Pkg().Path()+"."+obj.Name())
				return true
			}
			if obj.Pkg() != pkg {
				return true
			}
			if auditNetworkFuncs[obj.Name()] {
				violations = append(violations, path(cur)+" reaches "+obj.Name())
			}
			switch obj.(type) {
			case *types.Func, *types.Var:
				if _, ok := decl[obj]; ok && !seen[obj] {
					seen[obj] = true
					parent[obj] = cur
					queue = append(queue, obj)
				}
			}
			return true
		})
	}
	sort.Strings(violations)
	reachedNames = map[string]bool{}
	for o := range seen {
		reachedNames[o.Name()] = true
	}
	return violations, reachedNames
}
