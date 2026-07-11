package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
)

func sampleManifest(signed bool) *pkgformat.Manifest {
	return &pkgformat.Manifest{
		Name: "demo", Version: "1.0.0", Digest: "sha256:abc123", Signed: signed, FileCount: 2,
		Files: []pkgformat.FileEntry{
			{Path: "app/server.py", Type: "python", SHA256: "aaa"},
			{Path: "k8s/deploy.yaml", Type: "k8s-manifest", SHA256: "bbb"},
		},
	}
}

func TestCollectReflectsSignedState(t *testing.T) {
	unsigned := Collect(sampleManifest(false), time.Unix(0, 0))
	if got := statusOf(unsigned, "SR-11"); got != Partial {
		t.Errorf("SR-11 (unsigned) = %s, want partial", got)
	}
	signed := Collect(sampleManifest(true), time.Unix(0, 0))
	if got := statusOf(signed, "SR-11"); got != Satisfied {
		t.Errorf("SR-11 (signed) = %s, want satisfied", got)
	}
	if got := statusOf(unsigned, "CM-8"); got != Satisfied {
		t.Errorf("CM-8 = %s, want satisfied", got)
	}
}

func TestExportWritesRealFiles(t *testing.T) {
	b := Collect(sampleManifest(false), time.Unix(0, 0))
	dir := t.TempDir()

	written, err := Export(b, dir)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(written) != 3 {
		t.Fatalf("wrote %d files, want 3", len(written))
	}
	for _, p := range written {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file missing: %s (%v)", p, err)
		}
	}

	// evidence.json parses and carries the real digest + inventory.
	data, err := os.ReadFile(filepath.Join(dir, "demo", "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc Bundle
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("evidence.json is not valid JSON: %v", err)
	}
	if doc.Artifact.Digest != "sha256:abc123" {
		t.Errorf("digest = %q, want sha256:abc123", doc.Artifact.Digest)
	}
	if len(doc.Inventory) != 2 {
		t.Errorf("inventory = %d, want 2", len(doc.Inventory))
	}

	// oscal file parses as JSON and has an assessment-results root.
	od, err := os.ReadFile(filepath.Join(dir, "demo", "oscal-assessment-results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(od, &raw); err != nil {
		t.Fatalf("oscal file is not valid JSON: %v", err)
	}
	if _, ok := raw["assessment-results"]; !ok {
		t.Errorf("oscal file missing assessment-results root")
	}
}

func oscalJSONFor(t *testing.T, m *pkgformat.Manifest) []byte {
	t.Helper()
	data, err := marshal(oscalFrom(Collect(m, time.Unix(0, 0))))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOSCALValidatesAgainstNISTSchema(t *testing.T) {
	cases := map[string]*pkgformat.Manifest{
		"unsigned": sampleManifest(false),
		"signed":   sampleManifest(true),
	}
	withScan := sampleManifest(true)
	withScan.Scan = &pkgformat.ScanRef{Source: "grype", Total: 3, Counts: map[string]int{"high": 1, "medium": 1, "low": 1}}
	cases["signed+scan"] = withScan

	for name, m := range cases {
		if err := ValidateOSCAL(oscalJSONFor(t, m)); err != nil {
			t.Errorf("%s: generated OSCAL failed NIST schema validation: %v", name, err)
		}
	}
}

func TestValidateOSCALRejectsInvalid(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(oscalJSONFor(t, sampleManifest(true)), &doc); err != nil {
		t.Fatal(err)
	}
	// Drop the required reviewed-controls from the first result.
	ar := doc["assessment-results"].(map[string]any)
	res0 := ar["results"].([]any)[0].(map[string]any)
	delete(res0, "reviewed-controls")
	broken, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOSCAL(broken); err == nil {
		t.Error("expected schema validation to reject a result missing reviewed-controls")
	}
}

func statusOf(b *Bundle, id string) ControlStatus {
	for _, c := range b.Controls {
		if c.ID == id {
			return c.Status
		}
	}
	return "MISSING"
}
