package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
)

// makeVault seals a tiny source tree (with the given workload manifests) into a
// vault and returns its path. No images are pulled, so no registry is touched.
func makeVault(t *testing.T, workloads []string) string {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "app.py"), []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, w := range workloads {
		p := filepath.Join(src, filepath.FromSlash(w))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("kind: Deployment\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Create writes into the working directory; run it in a scratch cwd.
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(prev)

	_, out, err := pkgformat.Create(src, pkgformat.CreateOptions{
		Name:      "dep",
		Version:   "1.0.0",
		Workloads: workloads,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return filepath.Join(dir, out)
}

func TestPushImagesRequiresSealedLayout(t *testing.T) {
	vault := makeVault(t, nil)
	// No --pull-images at create time, so there is no layout to push. This must
	// fail before any registry I/O.
	_, err := PushImages(vault, "reg.enclave:5000")
	if err == nil {
		t.Fatal("PushImages succeeded on a vault with no sealed image layout")
	}
	if !strings.Contains(err.Error(), "no sealed image layout") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestApplyWorkloadsNeedsKubectl(t *testing.T) {
	vault := makeVault(t, []string{"k8s/deployment.yaml"})
	_, err := ApplyWorkloads(vault, []string{"k8s/deployment.yaml"}, ApplyOptions{
		Kubectl: "kubectl-definitely-not-installed-xyz",
	})
	if err == nil {
		t.Fatal("ApplyWorkloads succeeded without kubectl on PATH")
	}
	if !strings.Contains(err.Error(), "not found on PATH") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestApplyWorkloadsNoWorkloadsIsNoop(t *testing.T) {
	out, err := ApplyWorkloads("ignored.caisson", nil, ApplyOptions{})
	if err != nil {
		t.Errorf("empty workloads should be a no-op, got %v", err)
	}
	if out != "" {
		t.Errorf("expected no output, got %q", out)
	}
}
