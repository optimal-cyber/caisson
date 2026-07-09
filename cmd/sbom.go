package cmd

import (
	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/spf13/cobra"
)

const sbomDisplayLimit = 40

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Work with the SBOM sealed inside a vault",
	Long:  "Inspect the software bill of materials that travels inside a .caisson vault.",
}

var sbomViewCmd = &cobra.Command{
	Use:   "view [package]",
	Short: "Print the component inventory carried by a sealed vault",
	Long: `Render the inventory sealed inside the vault.

Real today: the per-file SHA-256 inventory read straight from the vault manifest.
Later milestone: a full dependency SBOM (SPDX / CycloneDX via Syft).`,
	Args: cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		m, err := pkgformat.Open(path)
		if err != nil {
			return err
		}
		note(c, "sbom view: %s  (%d files, digest %s)\n", path, m.FileCount, short(m.Digest))
		note(c, "  %-34s %10s  %-13s %s", "PATH", "SIZE", "TYPE", "SHA-256")
		shown := m.Files
		if len(shown) > sbomDisplayLimit {
			shown = shown[:sbomDisplayLimit]
		}
		for _, f := range shown {
			note(c, "  %-34s %10s  %-13s %s", f.Path, humanSize(f.Size), f.Type, short(f.SHA256))
		}
		if len(m.Files) > sbomDisplayLimit {
			note(c, "  … %d more", len(m.Files)-sbomDisplayLimit)
		}
		note(c, "\n  (file-level inventory · dependency SBOM via Syft is a later milestone)")
		return nil
	},
}

func init() {
	sbomCmd.AddCommand(sbomViewCmd)
}
