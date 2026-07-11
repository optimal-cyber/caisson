package cmd

import (
	"time"

	"github.com/optimal-cyber/caisson/internal/evidence"
	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/spf13/cobra"
)

var evidenceOut string

var evidenceCmd = &cobra.Command{
	Use:   "evidence",
	Short: "Work with the compliance evidence sealed inside a vault",
	Long:  "Collect and export the NIST 800-53 / CMMC control evidence that travels with a .caisson vault.",
}

var evidenceExportCmd = &cobra.Command{
	Use:   "export [package]",
	Short: "Export the assessment-ready evidence bundle to disk",
	Long: `Export compliance evidence for assessors and ISSMs.

Reads the sealed vault and writes an evidence bundle to disk, derived from the
artifact's real content digest and inventory:

  <out>/<name>/evidence.json                  Caisson-native evidence document
  <out>/<name>/oscal-assessment-results.json  OSCAL-aligned assessment results
  <out>/<name>/evidence.md                     human-readable report

The control mapping is rule-based and reflects real state (for example, the
signing control stays "partial" until cosign signing lands). The OSCAL
assessment-results file is validated against NIST's published OSCAL schema
before it is written. This is evidence to support an assessment — not an ATO.`,
	Args: cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		m, err := pkgformat.Open(path)
		if err != nil {
			return err
		}
		bundle := evidence.Collect(m, time.Now().UTC())
		written, err := evidence.Export(bundle, evidenceOut)
		if err != nil {
			return err
		}
		sum := bundle.Summary()
		note(c, "evidence export: %s\n", path)
		note(c, "  artifact    %s v%s", m.Name, m.Version)
		note(c, "  digest      %s", m.Digest)
		note(c, "  frameworks  %s", frameworks(bundle.Frameworks))
		note(c, "  controls    %d mapped  (%d satisfied, %d partial, %d planned, %d inherited)",
			len(bundle.Controls), sum[evidence.Satisfied], sum[evidence.Partial], sum[evidence.Planned], sum[evidence.Inherited])
		note(c, "")
		note(c, "  %-8s %-10s %s", "CONTROL", "STATUS", "TITLE")
		for _, ctrl := range bundle.Controls {
			note(c, "  %-8s %-10s %s", ctrl.ID, ctrl.Status, ctrl.Title)
		}
		note(c, "\n  wrote %d files:", len(written))
		for _, w := range written {
			note(c, "    %s", w)
		}
		note(c, "  ✓ OSCAL assessment-results validated against NIST OSCAL %s schema", evidence.OSCALVersion)
		note(c, "\n  (rule-based mapping · schema-validated OSCAL %s · not an ATO)", evidence.OSCALVersion)
		return nil
	},
}

func frameworks(fw []evidence.Framework) string {
	parts := make([]string, len(fw))
	for i, f := range fw {
		parts[i] = string(f)
	}
	return joinComma(parts)
}

func init() {
	evidenceExportCmd.Flags().StringVar(&evidenceOut, "out", "./evidence", "directory to write the evidence bundle into")
	evidenceCmd.AddCommand(evidenceExportCmd)
}
