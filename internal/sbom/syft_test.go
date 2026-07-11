package sbom

import (
	"strings"
	"testing"
	"time"
)

// a minimal Syft-style CycloneDX document (spec 1.5 to prove we keep syft's version).
const syftCDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {"tools": {"components": [{"type": "application", "name": "syft"}]}},
  "components": [
    {"type": "library", "name": "flask", "version": "3.0.3", "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
    {"type": "library", "name": "openssl", "version": "3.0.13"},
    {"type": "operating-system", "name": "debian", "version": "12"}
  ]
}`

func TestParseCycloneDXKeepsBytesAndCounts(t *testing.T) {
	r, err := parseCycloneDX([]byte(syftCDX), GenSyft)
	if err != nil {
		t.Fatalf("parseCycloneDX: %v", err)
	}
	if r.Generator != GenSyft {
		t.Errorf("generator = %q, want %q", r.Generator, GenSyft)
	}
	if r.Components != 3 {
		t.Errorf("components = %d, want 3", r.Components)
	}
	if r.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want the source's 1.5 (verbatim)", r.SpecVersion)
	}
	// The original bytes are preserved verbatim (so the attestation matches),
	// keeping syft-only detail like licenses and OS packages.
	if string(r.JSON) != syftCDX {
		t.Error("parseCycloneDX did not preserve the original bytes")
	}
	if !strings.Contains(string(r.JSON), "BSD-3-Clause") {
		t.Error("license detail lost")
	}
}

func TestParseCycloneDXRejectsNonCDX(t *testing.T) {
	if _, err := parseCycloneDX([]byte(`{"bomFormat":"SPDX"}`), GenSyft); err == nil {
		t.Error("expected rejection of a non-CycloneDX document")
	}
	if _, err := parseCycloneDX([]byte(`not json`), GenSyft); err == nil {
		t.Error("expected rejection of invalid JSON")
	}
}

func TestRunSyftMissingBinary(t *testing.T) {
	// The syft-not-installed path must fail fast and clearly, offline.
	_, err := runSyft("syft-definitely-not-installed-xyz", t.TempDir())
	if err == nil {
		t.Fatal("expected an error when syft is not on PATH")
	}
	if !strings.Contains(err.Error(), "not found on PATH") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCollectNativeFallback(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "flask==3.0.3\ngunicorn==22.0.0\n")

	r, err := Collect(dir, "demo", "1.0.0", time.Unix(0, 0), false)
	if err != nil {
		t.Fatalf("Collect(native): %v", err)
	}
	if r.Generator != GenNative {
		t.Errorf("generator = %q, want %q", r.Generator, GenNative)
	}
	if r.Components < 2 {
		t.Errorf("components = %d, want >= 2", r.Components)
	}
	if r.SpecVersion != SpecVersion {
		t.Errorf("specVersion = %q, want %q", r.SpecVersion, SpecVersion)
	}
	if len(r.JSON) == 0 {
		t.Error("native SBOM JSON is empty")
	}
}
