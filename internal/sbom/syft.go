package sbom

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Generator identifies how a Result's SBOM was produced.
const (
	GenNative = "caisson-native"
	GenSyft   = "syft"
)

// Result is a produced SBOM ready to seal: the exact document bytes to embed
// (and attest), plus a summary. JSON is what lands in the vault verbatim, so the
// SBOM attestation predicate and the embedded sbom.cdx.json are byte-identical.
type Result struct {
	Generator   string // GenNative or GenSyft
	Format      string // "CycloneDX"
	SpecVersion string
	Components  int
	JSON        []byte
}

// Collect produces an SBOM for dir. With useSyft it shells out to Anchore Syft
// for deep resolution (transitive deps, OS packages, licenses); otherwise it
// uses Caisson's native manifest detection. Syft is wrapped, not reimplemented —
// it must be on PATH, and this is the one path that needs an external tool.
func Collect(dir, name, version string, now time.Time, useSyft bool) (*Result, error) {
	if useSyft {
		return runSyft("syft", dir)
	}
	doc, err := Generate(dir, name, version, now)
	if err != nil {
		return nil, err
	}
	js, err := doc.JSON()
	if err != nil {
		return nil, err
	}
	return &Result{
		Generator:   GenNative,
		Format:      Format,
		SpecVersion: SpecVersion,
		Components:  len(doc.Components),
		JSON:        js,
	}, nil
}

// runSyft runs `<bin> scan dir:<dir> -o cyclonedx-json` and parses the result.
// bin is a parameter so the not-found path is testable without syft installed.
func runSyft(bin, dir string) (*Result, error) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("sbom: %q not found on PATH (needed for --syft): %w", bin, err)
	}
	out, err := exec.Command(path, "scan", "dir:"+dir, "-o", "cyclonedx-json").Output()
	if err != nil {
		return nil, fmt.Errorf("sbom: syft failed: %w", err)
	}
	return parseCycloneDX(out, GenSyft)
}

// parseCycloneDX reads a CycloneDX JSON document (e.g. Syft output) into a
// Result, keeping the original bytes verbatim so nothing is lost on the way into
// the vault.
func parseCycloneDX(data []byte, generator string) (*Result, error) {
	var probe struct {
		BOMFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("sbom: SBOM is not valid CycloneDX JSON: %w", err)
	}
	if probe.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("sbom: expected CycloneDX SBOM, got bomFormat %q", probe.BOMFormat)
	}
	spec := probe.SpecVersion
	if spec == "" {
		spec = SpecVersion
	}
	return &Result{
		Generator:   generator,
		Format:      Format,
		SpecVersion: spec,
		Components:  len(probe.Components),
		JSON:        data,
	}, nil
}
