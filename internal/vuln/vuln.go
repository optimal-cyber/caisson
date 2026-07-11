// Package vuln ingests a vulnerability scan report (Grype or Trivy JSON) into a
// normalized findings model so the scan travels sealed with the vault.
//
// It does NOT run a scanner or download a vulnerability database — that needs
// network/infra. Instead it ingests a report you produced (e.g. `grype <img> -o
// json` or `trivy image -f json`). Standard-library only, so it runs
// disconnected.
package vuln

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Severity is a normalized vulnerability severity.
type Severity string

const (
	Critical   Severity = "critical"
	High       Severity = "high"
	Medium     Severity = "medium"
	Low        Severity = "low"
	Negligible Severity = "negligible"
	Unknown    Severity = "unknown"
)

var rank = map[Severity]int{Unknown: 0, Negligible: 0, Low: 1, Medium: 2, High: 3, Critical: 4}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return rank[s] >= rank[min] }

// ParseSeverity normalizes a scanner severity string.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return Critical
	case "high":
		return High
	case "medium", "moderate":
		return Medium
	case "low":
		return Low
	case "negligible", "none":
		return Negligible
	default:
		return Unknown
	}
}

// Finding is one normalized vulnerability match.
type Finding struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Package  string   `json:"package"`
	Version  string   `json:"version,omitempty"`
	FixedIn  string   `json:"fixedIn,omitempty"`
}

// Report is a normalized scan report.
type Report struct {
	Source   string    `json:"source"`
	Findings []Finding `json:"findings"`
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[string(f.Severity)]++
	}
	return out
}

// JSON renders the normalized report.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// CountAtLeastIn totals the findings in a per-severity count map that are at
// least min severity. Handy for policy gates that only have the manifest counts.
func CountAtLeastIn(counts map[string]int, min Severity) int {
	n := 0
	for sev, c := range counts {
		if Severity(sev).AtLeast(min) {
			n += c
		}
	}
	return n
}

// Parse detects and parses a Grype or Trivy JSON report.
func Parse(data []byte) (*Report, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("vuln: not valid JSON: %w", err)
	}
	if _, ok := probe["matches"]; ok {
		return parseGrype(data)
	}
	if _, ok := probe["Results"]; ok {
		return parseTrivy(data)
	}
	return nil, errors.New("vuln: unrecognized report (expected Grype 'matches' or Trivy 'Results')")
}

func parseGrype(data []byte) (*Report, error) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Fix      struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	r := &Report{Source: "grype"}
	for _, m := range doc.Matches {
		r.Findings = append(r.Findings, Finding{
			ID:       m.Vulnerability.ID,
			Severity: ParseSeverity(m.Vulnerability.Severity),
			Package:  m.Artifact.Name,
			Version:  m.Artifact.Version,
			FixedIn:  strings.Join(m.Vulnerability.Fix.Versions, ", "),
		})
	}
	sortFindings(r.Findings)
	return r, nil
}

func parseTrivy(data []byte) (*Report, error) {
	var doc struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				Severity         string `json:"Severity"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	r := &Report{Source: "trivy"}
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			r.Findings = append(r.Findings, Finding{
				ID:       v.VulnerabilityID,
				Severity: ParseSeverity(v.Severity),
				Package:  v.PkgName,
				Version:  v.InstalledVersion,
				FixedIn:  v.FixedVersion,
			})
		}
	}
	sortFindings(r.Findings)
	return r, nil
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if rank[f[i].Severity] != rank[f[j].Severity] {
			return rank[f[i].Severity] > rank[f[j].Severity]
		}
		return f[i].ID < f[j].ID
	})
}
