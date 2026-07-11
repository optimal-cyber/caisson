// Package evidence handles compliance evidence for a sealed vault: it derives a
// control mapping from the artifact's real content digest and inventory, and
// writes an assessment-ready bundle (a Caisson-native JSON document, a
// human-readable report, and an OSCAL-aligned assessment-results file) to disk.
//
// The control mapping is rule-based — computed from what the vault actually
// carries, reflecting real state (e.g. the signing control is only "partial"
// while the manifest is unsigned). It is not a full assessment engine and none
// of this is an ATO, but the OSCAL assessment-results output is validated
// against NIST's published OSCAL schema (see oscal_validate.go) before it is
// written. Validation runs fully offline against the bundled schema.
package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
)

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
	Planned       ControlStatus = "planned"
	Inherited     ControlStatus = "inherited"
	NotApplicable ControlStatus = "n/a"
)

// Control is a single mapped compliance control with its supporting evidence.
type Control struct {
	ID        string        `json:"id"`
	Title     string        `json:"title"`
	Framework Framework     `json:"framework"`
	Status    ControlStatus `json:"status"`
	Rationale string        `json:"rationale"`
	Evidence  []string      `json:"evidence,omitempty"`
}

// Artifact identifies the sealed vault the evidence is about.
type Artifact struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Digest    string `json:"digest"`
	Signed    bool   `json:"signed"`
	FileCount int    `json:"fileCount"`
}

// InventoryItem is one payload file recorded in the evidence document.
type InventoryItem struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	SHA256 string `json:"sha256"`
}

// Bundle is the in-memory (and on-disk, as evidence.json) evidence for one vault.
type Bundle struct {
	Schema     string          `json:"schema"`
	Generated  string          `json:"generated"`
	Artifact   Artifact        `json:"artifact"`
	Frameworks []Framework     `json:"frameworks"`
	Controls   []Control       `json:"controls"`
	Inventory  []InventoryItem `json:"inventory"`
}

// Summary counts controls by status for a quick rollup.
func (b *Bundle) Summary() map[ControlStatus]int {
	out := map[ControlStatus]int{}
	for _, c := range b.Controls {
		out[c.Status]++
	}
	return out
}

// Collect derives an evidence bundle from a sealed manifest.
func Collect(m *pkgformat.Manifest, now time.Time) *Bundle {
	digestRef := "content digest " + m.Digest
	inventoryRef := fmt.Sprintf("sealed inventory (%d files, manifest.json)", m.FileCount)

	sbomRef := "file inventory"
	sbomRationale := ""
	if m.SBOM != nil {
		sbomRef = fmt.Sprintf("%s %s SBOM (%d components, sbom.cdx.json)", m.SBOM.Format, m.SBOM.SpecVersion, m.SBOM.Components)
		sbomRationale = fmt.Sprintf(" A %s %s SBOM enumerating %d dependency components travels sealed inside the vault.", m.SBOM.Format, m.SBOM.SpecVersion, m.SBOM.Components)
	}

	controls := []Control{
		{
			ID: "CM-8", Title: "System Component Inventory", Framework: NIST80053,
			Status:    Satisfied,
			Rationale: fmt.Sprintf("The vault carries a sealed inventory of %d files, each with a recorded SHA-256.%s", m.FileCount, sbomRationale),
			Evidence:  []string{inventoryRef, sbomRef},
		},
		{
			ID: "SI-7", Title: "Software, Firmware, and Information Integrity", Framework: NIST80053,
			Status:    Satisfied,
			Rationale: "A content digest over every payload file is sealed in the manifest; deploy verifies it before applying.",
			Evidence:  []string{digestRef, "per-file SHA-256 inventory"},
		},
		{
			ID: "SA-12", Title: "Supply Chain Protection", Framework: NIST80053,
			Status:    Satisfied,
			Rationale: "The application and its declared contents travel as one sealed, integrity-checked artifact across the airgap, with a bill of materials bound to the manifest.",
			Evidence:  []string{"manifest.json", digestRef, sbomRef},
		},
		componentAuthenticity(m, digestRef),
		vulnControl(m),
		{
			ID: "AC-4", Title: "Information Flow Enforcement", Framework: CMMC,
			Status:    Inherited,
			Rationale: "Airgap boundary controls are inherited from the enclave.",
		},
	}

	inv := make([]InventoryItem, 0, len(m.Files))
	for _, f := range m.Files {
		inv = append(inv, InventoryItem{Path: f.Path, Type: f.Type, SHA256: f.SHA256})
	}

	return &Bundle{
		Schema:     "caisson.evidence/v0.1",
		Generated:  now.UTC().Format(time.RFC3339),
		Artifact:   Artifact{Name: m.Name, Version: m.Version, Digest: m.Digest, Signed: m.Signed, FileCount: m.FileCount},
		Frameworks: []Framework{NIST80053, CMMC},
		Controls:   controls,
		Inventory:  inv,
	}
}

// vulnControl reflects whether a vulnerability scan is sealed in the vault.
func vulnControl(m *pkgformat.Manifest) Control {
	c := Control{ID: "RA-5", Title: "Vulnerability Monitoring and Scanning", Framework: NIST80053}
	if m.Scan == nil {
		c.Status = Planned
		c.Rationale = "No vulnerability scan is attached to this vault; attach one with --scan-report to satisfy this control and enable deploy-time policy gates."
		return c
	}
	c.Status = Satisfied
	c.Rationale = fmt.Sprintf("A %s vulnerability scan is sealed in the vault (%d findings: %s), enabling policy gates at deploy time.", m.Scan.Source, m.Scan.Total, summarizeCounts(m.Scan.Counts))
	c.Evidence = []string{fmt.Sprintf("%s scan report (scan.json)", m.Scan.Source)}
	return c
}

func summarizeCounts(counts map[string]int) string {
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return "0 findings"
	}
	return strings.Join(parts, ", ")
}

// componentAuthenticity reflects the vault's real signing state honestly.
func componentAuthenticity(m *pkgformat.Manifest, digestRef string) Control {
	c := Control{ID: "SR-11", Title: "Component Authenticity", Framework: NIST80053}
	if m.Signed {
		c.Status = Satisfied
		c.Rationale = "The manifest is cryptographically signed (Ed25519) and carries a DSSE-wrapped SLSA provenance attestation; authenticity and provenance are verifiable on arrival."
		c.Evidence = []string{"Ed25519 manifest signature", "SLSA provenance attestation", digestRef}
	} else {
		c.Status = Partial
		c.Rationale = "Integrity is protected by a content digest, but the manifest is not yet cryptographically signed (cosign integration pending)."
		c.Evidence = []string{digestRef}
	}
	return c
}

// Export writes the evidence bundle to outDir/<name>/ and returns the paths
// written: a native JSON document, an OSCAL-aligned assessment-results file, and
// a human-readable Markdown report.
func Export(b *Bundle, outDir string) ([]string, error) {
	dir := filepath.Join(outDir, b.Artifact.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var written []string

	nativeJSON, err := marshal(b)
	if err != nil {
		return written, err
	}
	p, err := writeOut(dir, "evidence.json", nativeJSON)
	if err != nil {
		return written, err
	}
	written = append(written, p)

	oscalJSON, err := marshal(oscalFrom(b))
	if err != nil {
		return written, err
	}
	// Fail closed: never write an OSCAL file that doesn't validate against the
	// bundled NIST schema.
	if err := ValidateOSCAL(oscalJSON); err != nil {
		return written, err
	}
	p, err = writeOut(dir, "oscal-assessment-results.json", oscalJSON)
	if err != nil {
		return written, err
	}
	written = append(written, p)

	p, err = writeOut(dir, "evidence.md", []byte(renderMarkdown(b)))
	if err != nil {
		return written, err
	}
	written = append(written, p)

	return written, nil
}

func writeOut(dir, name string, data []byte) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

func marshal(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func renderMarkdown(b *Bundle) string {
	var s strings.Builder
	fmt.Fprintf(&s, "# Caisson evidence — %s v%s\n\n", b.Artifact.Name, b.Artifact.Version)
	fmt.Fprintf(&s, "_Generated %s_\n\n", b.Generated)

	s.WriteString("## Artifact\n\n")
	fmt.Fprintf(&s, "- **Content digest:** `%s`\n", b.Artifact.Digest)
	fmt.Fprintf(&s, "- **Signed:** %t\n", b.Artifact.Signed)
	fmt.Fprintf(&s, "- **Files sealed:** %d\n\n", b.Artifact.FileCount)

	fmt.Fprintf(&s, "## Control coverage — %s\n\n", frameworksList(b.Frameworks))
	s.WriteString("| Control | Framework | Status | Rationale |\n|---|---|---|---|\n")
	for _, c := range b.Controls {
		fmt.Fprintf(&s, "| %s | %s | %s | %s |\n", c.ID, c.Framework, c.Status, c.Rationale)
	}

	s.WriteString("\n### Evidence references\n\n")
	for _, c := range b.Controls {
		if len(c.Evidence) == 0 {
			continue
		}
		fmt.Fprintf(&s, "- **%s** — %s\n", c.ID, strings.Join(c.Evidence, "; "))
	}

	s.WriteString("\n## Sealed inventory\n\n")
	s.WriteString("| Path | Type | SHA-256 |\n|---|---|---|\n")
	for _, it := range b.Inventory {
		fmt.Fprintf(&s, "| `%s` | %s | `%s` |\n", it.Path, it.Type, it.SHA256)
	}

	s.WriteString("\n---\n\n")
	fmt.Fprintf(&s, "_Control mapping is rule-based, derived from the sealed artifact. The OSCAL assessment-results file is validated against NIST's OSCAL %s schema. This is evidence to support an assessment — not an ATO._\n", OSCALVersion)
	return s.String()
}

func frameworksList(fw []Framework) string {
	parts := make([]string, len(fw))
	for i, f := range fw {
		parts[i] = string(f)
	}
	return strings.Join(parts, ", ")
}

// --- OSCAL assessment-results --------------------------------------------------
//
// An OSCAL assessment-results document that validates against NIST's published
// schema (see oscal_validate.go). UUIDs are derived deterministically from the
// content digest so output is reproducible for the same artifact.

type oscalDoc struct {
	AssessmentResults oscalAR `json:"assessment-results"`
}

type oscalAR struct {
	UUID     string        `json:"uuid"`
	Metadata oscalMeta     `json:"metadata"`
	ImportAP oscalHref     `json:"import-ap"`
	Results  []oscalResult `json:"results"`
}

type oscalMeta struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

type oscalHref struct {
	Href string `json:"href"`
}

type oscalResult struct {
	UUID             string                `json:"uuid"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Start            string                `json:"start"`
	ReviewedControls oscalReviewedControls `json:"reviewed-controls"`
	Observations     []oscalObs            `json:"observations"`
	Findings         []oscalFinding        `json:"findings"`
}

type oscalReviewedControls struct {
	ControlSelections []oscalControlSelection `json:"control-selections"`
}

type oscalControlSelection struct {
	IncludeAll *oscalIncludeAll `json:"include-all,omitempty"`
}

type oscalIncludeAll struct{}

type oscalObs struct {
	UUID             string          `json:"uuid"`
	Description      string          `json:"description"`
	Methods          []string        `json:"methods"`
	Collected        string          `json:"collected"`
	RelevantEvidence []oscalEvidence `json:"relevant-evidence,omitempty"`
}

type oscalEvidence struct {
	Description string `json:"description"`
}

type oscalFinding struct {
	UUID        string      `json:"uuid"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Target      oscalTarget `json:"target"`
}

type oscalTarget struct {
	Type     string      `json:"type"`
	TargetID string      `json:"target-id"`
	Status   oscalStatus `json:"status"`
}

type oscalStatus struct {
	State string `json:"state"`
}

func oscalFrom(b *Bundle) oscalDoc {
	obs := make([]oscalObs, 0, len(b.Controls))
	findings := make([]oscalFinding, 0, len(b.Controls))
	for _, c := range b.Controls {
		var ev []oscalEvidence
		for _, e := range c.Evidence {
			ev = append(ev, oscalEvidence{Description: e})
		}
		obs = append(obs, oscalObs{
			UUID:             detUUID("obs:" + b.Artifact.Digest + ":" + c.ID),
			Description:      fmt.Sprintf("%s (%s): %s", c.ID, c.Title, c.Rationale),
			Methods:          []string{"EXAMINE"},
			Collected:        b.Generated,
			RelevantEvidence: ev,
		})
		findings = append(findings, oscalFinding{
			UUID:        detUUID("find:" + b.Artifact.Digest + ":" + c.ID),
			Title:       fmt.Sprintf("%s — %s", c.ID, c.Title),
			Description: c.Rationale,
			Target: oscalTarget{
				Type:     "objective-id",
				TargetID: strings.ToLower(c.ID) + "_obj",
				Status:   oscalStatus{State: oscalState(c.Status)},
			},
		})
	}
	return oscalDoc{
		AssessmentResults: oscalAR{
			UUID: detUUID("ar:" + b.Artifact.Digest),
			Metadata: oscalMeta{
				Title:        fmt.Sprintf("Caisson evidence — %s v%s (OSCAL %s)", b.Artifact.Name, b.Artifact.Version, OSCALVersion),
				LastModified: b.Generated,
				Version:      b.Artifact.Version,
				OSCALVersion: OSCALVersion,
			},
			ImportAP: oscalHref{Href: "caisson://sealed-manifest/" + b.Artifact.Digest},
			Results: []oscalResult{{
				UUID:        detUUID("result:" + b.Artifact.Digest),
				Title:       "Sealed-artifact control mapping",
				Description: "Rule-based control satisfaction derived from the sealed Caisson vault.",
				Start:       b.Generated,
				ReviewedControls: oscalReviewedControls{
					ControlSelections: []oscalControlSelection{{IncludeAll: &oscalIncludeAll{}}},
				},
				Observations: obs,
				Findings:     findings,
			}},
		},
	}
}

func oscalState(s ControlStatus) string {
	switch s {
	case Satisfied, Inherited:
		return "satisfied"
	default:
		return "not-satisfied"
	}
}

// detUUID derives a stable RFC-4122-shaped UUID from a seed (no randomness, so
// evidence output is reproducible for the same artifact).
func detUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
