package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
)

// makeChartVault seals a source tree containing a Helm chart subtree and returns
// the vault path.
func makeChartVault(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	files := map[string]string{
		"chart/Chart.yaml":            "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
		"chart/values.yaml":           "replicaCount: 1\n",
		"chart/templates/deploy.yaml": "kind: Deployment\n",
		"app.py":                      "print(1)\n",
	}
	for rel, body := range files {
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(prev)
	_, out, err := pkgformat.Create(src, pkgformat.CreateOptions{Name: "demo", Version: "1.0.0", Chart: "chart", Release: "demo"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return filepath.Join(dir, out)
}

func TestExtractPayloadTree(t *testing.T) {
	vault := makeChartVault(t)
	dest := t.TempDir()

	n, err := pkgformat.ExtractPayloadTree(vault, dest, "chart")
	if err != nil {
		t.Fatalf("ExtractPayloadTree: %v", err)
	}
	if n != 3 {
		t.Errorf("extracted %d chart files, want 3", n)
	}
	// The chart tree is reconstructed on disk...
	got, err := os.ReadFile(filepath.Join(dest, "chart", "Chart.yaml"))
	if err != nil {
		t.Fatalf("Chart.yaml not extracted: %v", err)
	}
	if !strings.Contains(string(got), "name: demo") {
		t.Errorf("Chart.yaml content wrong: %q", got)
	}
	// ...and files outside the subtree are not extracted.
	if _, err := os.Stat(filepath.Join(dest, "app.py")); err == nil {
		t.Error("app.py should not have been extracted (outside the chart subtree)")
	}
}

func TestExtractPayloadTreeMissingSubtree(t *testing.T) {
	vault := makeChartVault(t)
	n, err := pkgformat.ExtractPayloadTree(vault, t.TempDir(), "nope")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 files for a missing subtree, got %d", n)
	}
}

func TestApplyChartNeedsHelm(t *testing.T) {
	_, err := ApplyChart("ignored.caisson", "chart", "demo", ApplyOptions{Helm: "helm-definitely-not-installed-xyz"})
	if err == nil {
		t.Fatal("ApplyChart should fail without helm on PATH")
	}
	if !strings.Contains(err.Error(), "not found on PATH") {
		t.Errorf("unexpected error: %v", err)
	}
}
