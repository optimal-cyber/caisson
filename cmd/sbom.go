package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/optimal-cyber/caisson/internal/sbom"
	"github.com/spf13/cobra"
)

const sbomDisplayLimit = 60

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Work with the SBOM sealed inside a vault",
	Long:  "Inspect and export the CycloneDX software bill of materials that travels inside a .caisson vault.",
}

var sbomViewCmd = &cobra.Command{
	Use:   "view [package]",
	Short: "Print the CycloneDX component inventory carried by a sealed vault",
	Long: `Render the SBOM sealed inside the vault.

Reads the embedded CycloneDX 1.6 SBOM (dependency components detected from
go.mod / package.json / requirements.txt / Dockerfile). Falls back to the
file-level inventory for older vaults that predate embedded SBOMs.`,
	Args: cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		raw, ok, err := pkgformat.ReadSBOM(path)
		if err != nil {
			return err
		}
		if !ok {
			return sbomViewFallback(c, path)
		}
		var doc sbom.Document
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		note(c, "sbom view: %s  (%s %s · %d components)\n", path, doc.BOMFormat, doc.SpecVersion, len(doc.Components))
		note(c, "  %-42s %-14s %s", "COMPONENT", "VERSION", "TYPE")
		shown := doc.Components
		if len(shown) > sbomDisplayLimit {
			shown = shown[:sbomDisplayLimit]
		}
		for _, cmp := range shown {
			note(c, "  %-42s %-14s %s", cmp.Name, cmp.Version, cmp.Type)
		}
		if len(doc.Components) > sbomDisplayLimit {
			note(c, "  … %d more", len(doc.Components)-sbomDisplayLimit)
		}
		if len(doc.Components) == 0 {
			note(c, "  (no dependency manifests detected in the payload)")
		}
		note(c, "\n  (native manifest detection · deeper resolution via Syft is a later milestone)")
		return nil
	},
}

func sbomViewFallback(c *cobra.Command, path string) error {
	m, err := pkgformat.Open(path)
	if err != nil {
		return err
	}
	note(c, "sbom view: %s  (no embedded SBOM — showing file inventory)\n", path)
	note(c, "  %-40s %-12s %s", "PATH", "TYPE", "SHA-256")
	for _, f := range m.Files {
		note(c, "  %-40s %-12s %s", f.Path, f.Type, short(f.SHA256))
	}
	return nil
}

var sbomOut, sbomFormat string

var sbomExportCmd = &cobra.Command{
	Use:   "export [package]",
	Short: "Write the vault's SBOM to disk",
	Long:  "Extract the embedded CycloneDX SBOM from a vault and write it to a file.",
	Args:  cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		if sbomFormat != "cyclonedx" {
			return errUnsupportedFormat(sbomFormat)
		}
		raw, ok, err := pkgformat.ReadSBOM(path)
		if err != nil {
			return err
		}
		if !ok {
			return errNoSBOM(path)
		}
		m, err := pkgformat.Open(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(sbomOut, 0o755); err != nil {
			return err
		}
		dest := filepath.Join(sbomOut, m.Name+".cdx.json")
		if err := os.WriteFile(dest, raw, 0o644); err != nil {
			return err
		}
		note(c, "sbom export: %s", path)
		note(c, "  wrote CycloneDX SBOM → %s", dest)
		return nil
	},
}

func init() {
	sbomExportCmd.Flags().StringVar(&sbomOut, "out", ".", "directory to write the SBOM into")
	sbomExportCmd.Flags().StringVar(&sbomFormat, "format", "cyclonedx", "SBOM format (cyclonedx)")
	sbomCmd.AddCommand(sbomViewCmd, sbomExportCmd)
}
