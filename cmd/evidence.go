package cmd

import (
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
	Short: "Export the assessment-ready evidence bundle",
	Long: `Export compliance evidence for assessors and ISSMs.

Real today: reads the sealed vault and ties the evidence to its actual content
digest. Not yet implemented: the NIST 800-53 / CMMC control evaluation and the
OSCAL bundle output are placeholder mappings.`,
	Args: cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		m, err := pkgformat.Open(path)
		if err != nil {
			return err
		}
		bundle, err := evidence.Collect(m.Name)
		if err != nil {
			return err
		}
		dest, err := evidence.Export(bundle, evidenceOut)
		if err != nil {
			return err
		}
		sum := bundle.Summary()
		note(c, "evidence export: %s\n", path)
		note(c, "  artifact    %s v%s", m.Name, m.Version)
		note(c, "  digest      %s", m.Digest)
		note(c, "  frameworks  %v", bundle.Frameworks)
		note(c, "  controls    %d mapped  (%d satisfied, %d partial, %d inherited)",
			len(bundle.Controls), sum[evidence.Satisfied], sum[evidence.Partial], sum[evidence.Inherited])
		note(c, "")
		note(c, "  %-8s %-10s %s", "CONTROL", "STATUS", "TITLE")
		for _, ctrl := range bundle.Controls {
			note(c, "  %-8s %-10s %s", ctrl.ID, ctrl.Status, ctrl.Title)
		}
		note(c, "\n  [not implemented] control evaluation + OSCAL bundle are placeholder mappings")
		note(c, "  would write → %s/", dest)
		return nil
	},
}

func init() {
	evidenceExportCmd.Flags().StringVar(&evidenceOut, "out", "./evidence", "directory to write the evidence bundle into")
	evidenceCmd.AddCommand(evidenceExportCmd)
}
