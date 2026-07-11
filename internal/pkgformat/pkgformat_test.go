package pkgformat

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/optimal-cyber/caisson/internal/oci"
	"github.com/optimal-cyber/caisson/internal/signing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1random "github.com/google/go-containerregistry/pkg/v1/random"
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

func TestSignedVaultVerifies(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "app/server.py", "print('hi')\n")
	writeTmp(t, src, "k8s/deployment.yaml", "kind: Deployment\n")

	key, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer inDir(t, t.TempDir())()

	m, out, err := Create(src, CreateOptions{Name: "demo", Version: "1.0.0", Signer: key})
	if err != nil {
		t.Fatalf("Create(signed): %v", err)
	}
	if !m.Signed {
		t.Error("manifest.Signed = false for a signed vault")
	}

	pubPEM, _ := key.PublicPEM()
	res, err := VerifySignature(out, pubPEM)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if !res.Present || !res.Valid {
		t.Errorf("signature present=%t valid=%t, want both true", res.Present, res.Valid)
	}
	if res.IdentityMatch == nil || !*res.IdentityMatch {
		t.Error("identity did not match the signing key")
	}
	if !res.ProvenancePresent || !res.ProvenanceValid {
		t.Errorf("provenance present=%t valid=%t, want both true", res.ProvenancePresent, res.ProvenanceValid)
	}

	// A different key must NOT match identity.
	other, _ := signing.Generate()
	otherPub, _ := other.PublicPEM()
	res2, err := VerifySignature(out, otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if res2.IdentityMatch == nil || *res2.IdentityMatch {
		t.Error("identity matched an unrelated key")
	}
	// The signature itself is still internally valid (signed by the embedded key).
	if !res2.Valid {
		t.Error("embedded-key signature should still be valid regardless of provided key")
	}
}

func TestUnsignedVaultReportsNoSignature(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "a.txt", "x")
	defer inDir(t, t.TempDir())()

	_, out, err := Create(src, CreateOptions{Name: "plain"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifySignature(out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Present {
		t.Error("unsigned vault reported a signature")
	}
}

func TestCreateRecordsFrameworksAndImages(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "app/server.py", "print('hi')\n")
	defer inDir(t, t.TempDir())()

	_, out, err := Create(src, CreateOptions{
		Name:       "demo",
		Version:    "1.0.0",
		Frameworks: []string{"NIST SP 800-53 Rev 5", "CMMC 2.0 Level 2"},
		Images:     []string{"registry.airgap.local:5000/demo:1.0.0"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	m, err := Open(out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(m.Frameworks) != 2 || m.Frameworks[0] != "NIST SP 800-53 Rev 5" {
		t.Errorf("frameworks not sealed: %v", m.Frameworks)
	}
	if len(m.Images) != 1 {
		t.Fatalf("images not sealed: %v", m.Images)
	}
	if img := m.Images[0]; img.Reference != "registry.airgap.local:5000/demo:1.0.0" || img.Pulled {
		t.Errorf("declared image wrong: %+v", img)
	}

	// Frameworks and images ride inside the signed manifest, so the seal must
	// still verify.
	ok, _, err := Verify(out)
	if err != nil || !ok {
		t.Errorf("Verify ok=%t err=%v after recording frameworks/images", ok, err)
	}
}

func TestCreateEmbedsAndVerifiesImageLayout(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "app/server.py", "print('hi')\n")

	// Build a real OCI layout offline from an in-memory image — no registry.
	ref := "registry.airgap.local:5000/demo:1.0.0"
	img, err := v1random.Image(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	layoutDir := filepath.Join(t.TempDir(), oci.LayoutDir)
	pulled, err := oci.WriteLayout(layoutDir, map[string]v1.Image{ref: img})
	if err != nil {
		t.Fatalf("WriteLayout: %v", err)
	}

	defer inDir(t, t.TempDir())()
	_, out, err := Create(src, CreateOptions{
		Name:           "demo",
		Version:        "1.0.0",
		Images:         []string{ref},
		ImageLayoutDir: layoutDir,
		PulledDigests:  map[string]string{ref: pulled[0].Digest},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	m, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Images) != 1 || !m.Images[0].Pulled || m.Images[0].Digest != pulled[0].Digest {
		t.Fatalf("pulled image not recorded: %+v", m.Images)
	}
	if m.Images[0].Path != "images/" {
		t.Errorf("pulled image path = %q, want images/", m.Images[0].Path)
	}

	// The sealed layout verifies against the digest in the signed manifest.
	ok, _, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify = false for a vault with an intact embedded image layout")
	}
}

func TestVerifyDetectsTamperedEmbeddedImage(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "app/server.py", "print('hi')\n")

	ref := "registry.airgap.local:5000/demo:1.0.0"
	img, err := v1random.Image(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	layoutDir := filepath.Join(t.TempDir(), oci.LayoutDir)
	pulled, err := oci.WriteLayout(layoutDir, map[string]v1.Image{ref: img})
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt a layer blob on disk *before* sealing, while the manifest still
	// records the pristine digest — the sealed layout no longer matches.
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	lh, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(layoutDir, "blobs", "sha256", lh.Hex)
	if err := os.WriteFile(blob, []byte("tampered payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	defer inDir(t, t.TempDir())()
	_, out, err := Create(src, CreateOptions{
		Name:           "demo",
		Version:        "1.0.0",
		Images:         []string{ref},
		ImageLayoutDir: layoutDir,
		PulledDigests:  map[string]string{ref: pulled[0].Digest},
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, _, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("Verify = true for a vault whose embedded image layout was tampered")
	}
}

func TestVerifyFailsWhenPulledImageLayoutMissing(t *testing.T) {
	src := t.TempDir()
	writeTmp(t, src, "app/server.py", "print('hi')\n")
	defer inDir(t, t.TempDir())()

	// Manifest records a pulled image but no layout is embedded (ImageLayoutDir
	// omitted) — an inconsistency Verify must catch.
	_, out, err := Create(src, CreateOptions{
		Name:          "demo",
		Version:       "1.0.0",
		Images:        []string{"registry.airgap.local:5000/demo:1.0.0"},
		PulledDigests: map[string]string{"registry.airgap.local:5000/demo:1.0.0": "sha256:" + zeroDigest},
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, _, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("Verify = true although a pulled image is recorded with no sealed layout")
	}
}

const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

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
