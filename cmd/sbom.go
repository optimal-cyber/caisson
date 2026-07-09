package cmd

import (
	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/spf13/cobra"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Work with the SBOM sealed inside a vault",
	Long:  "Inspect the software bill of materials that travels inside a .caisson vault.",
}

var sbomViewCmd = &cobra.Command{
	Use:   "view [package]",
	Short: "Print the SBOM carried by a sealed vault",
	Long:  "Render the signed component inventory sealed inside the vault. Read-only.",
	Args:  cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		pkg, err := pkgformat.Inspect(path)
		if err != nil {
			return err
		}
		note(c, "sbom view: %s  (%d components, sealed under %s)\n", path, len(pkg.Components), pkg.Seal.Digest)
		note(c, "  %-26s %-10s %-16s %s", "COMPONENT", "VERSION", "TYPE", "LICENSE")
		for _, cmp := range pkg.Components {
			note(c, "  %-26s %-10s %-16s %s", cmp.Name, cmp.Version, cmp.Type, cmp.License)
		}
		note(c, "\n  formats (real impl): SPDX 2.3 / CycloneDX 1.6 · signature verified on read")
		note(c, "\n[scaffold] placeholder output — real SBOM read lives in internal/pkgformat")
		return nil
	},
}

func init() {
	sbomCmd.AddCommand(sbomViewCmd)
}
