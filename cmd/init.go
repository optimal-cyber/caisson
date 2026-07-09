package cmd

import (
	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold a caisson.yaml in the current project",
	Long: `Initialize a Caisson project.

Creates a caisson.yaml describing what to seal (source paths, images, workloads),
which compliance frameworks to map (NIST 800-53, CMMC), and the signing identity
to bind provenance to. Run this once at the root of the repo you intend to ship.`,
	Args: cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		note(c, "init: would scaffold a Caisson project in the current directory")
		note(c, "")
		note(c, "  would write   caisson.yaml")
		note(c, "  package name  my-app")
		note(c, "  vault output  my-app%s", pkgformat.Extension)
		note(c, "  frameworks    NIST SP 800-53 Rev 5, CMMC 2.0 Level 2")
		note(c, "  signing       cosign (keyless or key-based) — set in caisson.yaml")
		note(c, "")
		note(c, "  next:  caisson package create ./my-app")
		note(c, "\n[scaffold] not wired up yet — see internal/pkgformat")
		return nil
	},
}
