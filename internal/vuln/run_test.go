package vuln

import (
	"os/exec"
	"strings"
	"testing"
)

func TestScannerArgs(t *testing.T) {
	g, err := scannerArgs(ScannerGrype, "/src")
	if err != nil || strings.Join(g, " ") != "dir:/src -o json" {
		t.Errorf("grype args = %v (%v)", g, err)
	}
	tr, err := scannerArgs(ScannerTrivy, "/src")
	if err != nil || strings.Join(tr, " ") != "fs --format json --quiet /src" {
		t.Errorf("trivy args = %v (%v)", tr, err)
	}
	if _, err := scannerArgs("bogus", "/src"); err == nil {
		t.Error("expected error for an unsupported scanner")
	}
}

func TestRunUnsupportedScanner(t *testing.T) {
	if _, err := Run("bogus", t.TempDir()); err == nil {
		t.Error("Run should reject an unsupported scanner")
	}
}

func TestRunMissingScannerBinary(t *testing.T) {
	if _, err := exec.LookPath(ScannerGrype); err == nil {
		t.Skip("grype is installed; skipping the missing-binary guard test")
	}
	_, err := Run(ScannerGrype, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not found on PATH") {
		t.Errorf("want a not-found-on-PATH error, got %v", err)
	}
}
