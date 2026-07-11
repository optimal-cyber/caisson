package cmd

import (
	"fmt"
	"strings"
)

// joinComma joins parts with ", ".
func joinComma(parts []string) string { return strings.Join(parts, ", ") }

func errUnsupportedFormat(f string) error {
	return fmt.Errorf("unsupported SBOM format %q (only cyclonedx)", f)
}

func errNoSBOM(path string) error {
	return fmt.Errorf("no embedded SBOM found in %s", path)
}

// scanSummary renders per-severity counts in severity order, skipping zeros.
func scanSummary(counts map[string]int) []string {
	var out []string
	for _, sev := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if n := counts[sev]; n > 0 {
			out = append(out, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(out) == 0 {
		out = append(out, "0 findings")
	}
	return out
}

// humanSize renders a byte count as a compact human-readable string.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// short truncates a long hash for display.
func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12] + "…"
	}
	return sha
}
