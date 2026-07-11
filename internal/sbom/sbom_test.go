package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateDetectsManifests(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/spf13/cobra v1.8.1\n\tgithub.com/x/y v0.1.0 // indirect\n)\n")
	write(t, dir, "requirements.txt", "# comment\nflask==3.0.3\ngunicorn>=22.0.0\n-r other.txt\n")
	write(t, dir, "Dockerfile", "FROM python:3.13-slim\nWORKDIR /app\n")
	write(t, dir, "web/package.json", `{"dependencies":{"react":"^18.2.0"},"devDependencies":{"vite":"5.0.0"}}`)

	doc, err := Generate(dir, "demo", "1.0.0", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Errorf("bad header: %s %s", doc.BOMFormat, doc.SpecVersion)
	}

	want := map[string]string{
		"pkg:golang/github.com/spf13/cobra@v1.8.1": "library",
		"pkg:golang/github.com/x/y@v0.1.0":         "library",
		"pkg:pypi/flask@3.0.3":                     "library",
		"pkg:pypi/gunicorn@22.0.0":                 "library",
		"pkg:docker/python@3.13-slim":              "container",
		"pkg:npm/react@18.2.0":                     "library",
		"pkg:npm/vite@5.0.0":                       "library",
	}
	got := map[string]string{}
	for _, c := range doc.Components {
		got[c.PURL] = c.Type
	}
	for purl, typ := range want {
		if got[purl] != typ {
			t.Errorf("missing/wrong component %s (type %q, want %q)", purl, got[purl], typ)
		}
	}

	// Emits valid CycloneDX JSON.
	b, err := doc.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("SBOM is not valid JSON: %v", err)
	}
	if raw["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v", raw["bomFormat"])
	}
}

func TestGenerateDeterministic(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "flask==3.0.3\n")
	a, _ := Generate(dir, "d", "1", time.Unix(1, 0))
	b, _ := Generate(dir, "d", "1", time.Unix(2, 0))
	if a.SerialNumber != b.SerialNumber {
		t.Errorf("serial not deterministic: %s != %s", a.SerialNumber, b.SerialNumber)
	}
}
