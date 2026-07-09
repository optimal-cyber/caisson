package pkgformat

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateOpenVerify(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "app/server.py", "print('hi')\n")
	writeTmp(t, src, "k8s/deployment.yaml", "kind: Deployment\n")
	writeTmp(t, src, "README.md", "# demo\n")

	// Create writes into the working directory; run it in a scratch cwd.
	defer inDir(t, t.TempDir())()

	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	m, out, err := Create(src, CreateOptions{Name: "demo", Version: "1.0.0", Now: fixed})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if want := "demo" + Extension; out != want {
		t.Errorf("out = %q, want %q", out, want)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("vault not written to disk: %v", err)
	}
	if m.FileCount != 3 {
		t.Errorf("FileCount = %d, want 3", m.FileCount)
	}
	if m.Digest == "" || m.Digest == "sha256:" {
		t.Errorf("digest not computed: %q", m.Digest)
	}

	got, err := Open(out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Digest != m.Digest || got.FileCount != m.FileCount || got.Name != "demo" {
		t.Errorf("Open manifest mismatch: got %+v", got)
	}

	ok, _, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("Verify = false, want true for an untampered vault")
	}
}

func TestDigestIsDeterministic(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "a.txt", "alpha")
	writeTmp(t, src, "nested/b.txt", "beta")

	run := func(now time.Time) string {
		defer inDir(t, t.TempDir())()
		m, _, err := Create(src, CreateOptions{Name: "x", Now: now})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return m.Digest
	}

	// Same content, different timestamps → identical digest.
	if d1, d2 := run(time.Unix(1, 0)), run(time.Unix(999999, 0)); d1 != d2 {
		t.Errorf("digest not deterministic: %s != %s", d1, d2)
	}
}

func writeTmp(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// inDir changes into dir and returns a func that restores the previous cwd.
func inDir(t *testing.T, dir string) func() {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return func() { _ = os.Chdir(prev) }
}
