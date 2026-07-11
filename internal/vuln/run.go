package vuln

import (
	"fmt"
	"os/exec"
)

// Scanners are the vulnerability scanners Run can drive.
const (
	ScannerGrype = "grype"
	ScannerTrivy = "trivy"
)

// Run executes a supported scanner against a directory target and ingests its
// JSON output. It wraps the scanner you already run (grype or trivy) rather than
// reimplementing scanning or shipping a vulnerability database — the scanner
// must be on PATH, and it maintains its own DB. The not-found path fails fast.
func Run(scanner, dir string) (*Report, error) {
	args, err := scannerArgs(scanner, dir)
	if err != nil {
		return nil, err
	}
	bin, err := exec.LookPath(scanner)
	if err != nil {
		return nil, fmt.Errorf("vuln: %q not found on PATH (needed for --scan %s): %w", scanner, scanner, err)
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("vuln: %s failed: %w", scanner, err)
	}
	return Parse(out)
}

// scannerArgs builds the command arguments to emit JSON on stdout for a
// directory target. Split out from Run so the mapping is unit-testable without
// the scanner installed.
func scannerArgs(scanner, dir string) ([]string, error) {
	switch scanner {
	case ScannerGrype:
		// grype reads a directory target and emits its JSON on stdout.
		return []string{"dir:" + dir, "-o", "json"}, nil
	case ScannerTrivy:
		return []string{"fs", "--format", "json", "--quiet", dir}, nil
	default:
		return nil, fmt.Errorf("vuln: unsupported scanner %q (use %q or %q)", scanner, ScannerGrype, ScannerTrivy)
	}
}
