package vuln

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGrype(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "grype.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "grype" {
		t.Errorf("source = %q", r.Source)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(r.Findings))
	}
	// Sorted most-severe first.
	if r.Findings[0].Severity != Critical || r.Findings[0].Package != "flask" {
		t.Errorf("first finding = %+v, want critical flask", r.Findings[0])
	}
	counts := r.Counts()
	if counts["critical"] != 1 || counts["high"] != 1 || counts["medium"] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestParseTrivy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "trivy.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "trivy" || len(r.Findings) != 2 {
		t.Fatalf("source=%q findings=%d", r.Source, len(r.Findings))
	}
	if got := r.Findings[0].Severity; got != High {
		t.Errorf("first severity = %q, want high", got)
	}
}

func TestThreshold(t *testing.T) {
	counts := map[string]int{"critical": 1, "high": 2, "medium": 5, "low": 3}
	if n := CountAtLeastIn(counts, High); n != 3 {
		t.Errorf("count >= high = %d, want 3", n)
	}
	if n := CountAtLeastIn(counts, Critical); n != 1 {
		t.Errorf("count >= critical = %d, want 1", n)
	}
	if !High.AtLeast(Medium) || Low.AtLeast(High) {
		t.Error("severity ordering wrong")
	}
}

func TestParseUnknownFormat(t *testing.T) {
	if _, err := Parse([]byte(`{"foo":1}`)); err == nil {
		t.Error("expected error for unrecognized report")
	}
}
