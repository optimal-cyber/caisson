package oci

import (
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// buildImages makes n in-memory images keyed by reference. random.Image needs
// no network, so the whole OCI-layout path is exercised offline.
func buildImages(t *testing.T, refs ...string) map[string]v1.Image {
	t.Helper()
	out := make(map[string]v1.Image, len(refs))
	for i, ref := range refs {
		img, err := random.Image(1024, int64(i+1))
		if err != nil {
			t.Fatalf("random.Image: %v", err)
		}
		out[ref] = img
	}
	return out
}

func TestWriteLayoutRecordsDigests(t *testing.T) {
	imgs := buildImages(t, "registry.airgap.local/b:2", "registry.airgap.local/a:1")
	dir := filepath.Join(t.TempDir(), LayoutDir)

	pulled, err := WriteLayout(dir, imgs)
	if err != nil {
		t.Fatalf("WriteLayout: %v", err)
	}
	if len(pulled) != 2 {
		t.Fatalf("got %d pulled, want 2", len(pulled))
	}
	// Output is sorted by reference for determinism.
	if pulled[0].Reference != "registry.airgap.local/a:1" || pulled[1].Reference != "registry.airgap.local/b:2" {
		t.Errorf("not sorted by reference: %+v", pulled)
	}
	for _, p := range pulled {
		if want := imgs[p.Reference]; want != nil {
			dg, _ := want.Digest()
			if p.Digest != dg.String() {
				t.Errorf("%s digest = %s, want %s", p.Reference, p.Digest, dg)
			}
		}
	}

	// A real OCI layout was written to disk.
	for _, f := range []string{"oci-layout", "index.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("layout missing %s: %v", f, err)
		}
	}
}

func TestVerifyLayoutRoundTrip(t *testing.T) {
	imgs := buildImages(t, "registry.airgap.local/app:1.0.0")
	dir := filepath.Join(t.TempDir(), LayoutDir)
	pulled, err := WriteLayout(dir, imgs)
	if err != nil {
		t.Fatal(err)
	}
	digests := []string{pulled[0].Digest}
	if err := VerifyLayout(dir, digests); err != nil {
		t.Fatalf("VerifyLayout on an untampered layout: %v", err)
	}
}

func TestVerifyLayoutDetectsMissingImage(t *testing.T) {
	imgs := buildImages(t, "registry.airgap.local/app:1.0.0")
	dir := filepath.Join(t.TempDir(), LayoutDir)
	if _, err := WriteLayout(dir, imgs); err != nil {
		t.Fatal(err)
	}
	// A digest that was never written must be reported as missing.
	bogus := "sha256:" + "00000000000000000000000000000000000000000000000000000000000000ab"
	if err := VerifyLayout(dir, []string{bogus}); err == nil {
		t.Error("expected VerifyLayout to fail for a digest not in the layout")
	}
}

func TestVerifyLayoutDetectsTamperedBlob(t *testing.T) {
	ref := "registry.airgap.local/app:1.0.0"
	imgs := buildImages(t, ref)
	dir := filepath.Join(t.TempDir(), LayoutDir)
	pulled, err := WriteLayout(dir, imgs)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt a layer blob; its filename is the (now stale) content digest, so
	// re-hashing the blob no longer matches and validation must fail.
	layers, err := imgs[ref].Layers()
	if err != nil {
		t.Fatal(err)
	}
	lh, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(dir, "blobs", "sha256", lh.Hex)
	if err := os.WriteFile(blob, []byte("tampered payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := VerifyLayout(dir, []string{pulled[0].Digest}); err == nil {
		t.Error("expected VerifyLayout to detect the tampered layer blob")
	}
}
