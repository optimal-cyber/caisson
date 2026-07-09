// Package evidence handles compliance evidence: collecting NIST 800-53 / CMMC
// control mappings for a sealed package and exporting an assessment-ready
// bundle that travels with the payload.
//
// Scaffold status: types describe the real evidence model; Collect and Export
// return/echo placeholder data. Replace the bodies with real control
// evaluation and bundle serialization.
package evidence

import "fmt"

// Framework identifies a compliance framework the evidence maps to.
type Framework string

const (
	NIST80053 Framework = "NIST SP 800-53 Rev 5"
	CMMC      Framework = "CMMC 2.0 Level 2"
)

// ControlStatus is the assessed state of a single control.
type ControlStatus string

const (
	Satisfied     ControlStatus = "satisfied"
	Partial       ControlStatus = "partial"
	Inherited     ControlStatus = "inherited"
	NotApplicable ControlStatus = "n/a"
)

// Control is a single mapped compliance control with its supporting evidence.
type Control struct {
	ID        string
	Title     string
	Framework Framework
	Status    ControlStatus
	Rationale string
	Evidence  []string // artifact refs inside the package (SBOM entries, digests, logs)
}

// Bundle is the assessment-ready evidence package for one Caisson vault.
type Bundle struct {
	Package    string
	Generated  string // RFC3339
	Frameworks []Framework
	Controls   []Control
}

// Summary counts controls by status for a quick at-a-glance rollup.
func (b *Bundle) Summary() map[ControlStatus]int {
	out := map[ControlStatus]int{}
	for _, c := range b.Controls {
		out[c.Status]++
	}
	return out
}

// Collect gathers the control mappings sealed inside a package into a bundle.
// Scaffold: returns representative placeholder controls.
func Collect(pkgName string) (*Bundle, error) {
	return &Bundle{
		Package:    pkgName,
		Generated:  "2026-01-15T09:31:00Z",
		Frameworks: []Framework{NIST80053, CMMC},
		Controls: []Control{
			{ID: "SI-7", Title: "Software, Firmware, and Information Integrity", Framework: NIST80053, Status: Satisfied,
				Rationale: "Seal digest + cosign signature verify integrity end to end.", Evidence: []string{"seal.sig", "sbom.spdx.json"}},
			{ID: "SA-12", Title: "Supply Chain Protection", Framework: NIST80053, Status: Satisfied,
				Rationale: "Full SBOM with signed provenance travels inside the vault.", Evidence: []string{"sbom.spdx.json", "provenance.slsa.json"}},
			{ID: "CM-8", Title: "System Component Inventory", Framework: NIST80053, Status: Satisfied,
				Rationale: "Component inventory is the package manifest itself.", Evidence: []string{"manifest.json"}},
			{ID: "RA-5", Title: "Vulnerability Monitoring and Scanning", Framework: NIST80053, Status: Partial,
				Rationale: "Scan report attached; continuous monitoring is operator-owned post-deploy.", Evidence: []string{"scan.grype.json"}},
			{ID: "AC-4", Title: "Information Flow Enforcement", Framework: CMMC, Status: Inherited,
				Rationale: "Airgap boundary controls inherited from the enclave.", Evidence: []string{}},
		},
	}, nil
}

// Export writes an evidence bundle to outDir for assessors and ISSMs.
// Scaffold: reports the destination it would write to and returns that path.
func Export(b *Bundle, outDir string) (string, error) {
	if b == nil {
		return "", fmt.Errorf("evidence: nil bundle")
	}
	// Real implementation: render OSCAL + human-readable artifacts under outDir.
	return outDir, nil
}
