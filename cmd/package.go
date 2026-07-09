package cmd

import (
	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/spf13/cobra"
)

var packageCmd = &cobra.Command{
	Use:     "package",
	Aliases: []string{"pkg"},
	Short:   "Create and inspect sealed Caisson vaults",
	Long:    "Work with the .caisson vault: seal a source tree into one, or inspect what a sealed vault carries.",
}

var packageCreateCmd = &cobra.Command{
	Use:   "create [source]",
	Short: "Seal a source directory into a .caisson vault",
	Long: `Seal a release at the source.

Resolves the application's components, builds a signed SBOM, captures its images
and workloads, maps compliance controls, and locks everything behind a
cryptographic seal — computed once, here, on the connected side.`,
	Args: cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		src := args[0]
		pkg, err := pkgformat.Create(src)
		if err != nil {
			return err
		}
		note(c, "package create: sealing %q into a Caisson vault\n", src)
		note(c, "  ✓ resolved %d components · SBOM sealed", len(pkg.Components))
		note(c, "  ✓ captured %d images, %d workloads", len(pkg.Manifest.Images), len(pkg.Manifest.Workloads))
		note(c, "  ✓ mapped NIST 800-53 + CMMC control evidence · attached")
		note(c, "  ✓ provenance signed (%s) by %s", pkg.Seal.Algorithm, pkg.Seal.Signer)
		note(c, "  ✓ seal %s", pkg.Seal.Digest)
		note(c, "\n  vault ready → %s  (%s v%s)", pkg.Filename(), pkg.Name, pkg.Version)
		note(c, "\n[scaffold] placeholder output — real packing lives in internal/pkgformat")
		return nil
	},
}

var packageInspectCmd = &cobra.Command{
	Use:   "inspect [package]",
	Short: "Show what a sealed vault carries, without deploying it",
	Long:  "Open a .caisson vault and print its metadata, manifest, and seal — read-only, nothing is applied.",
	Args:  cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		pkg, err := pkgformat.Inspect(path)
		if err != nil {
			return err
		}
		note(c, "package inspect: %s\n", path)
		note(c, "  name        %s", pkg.Name)
		note(c, "  version     %s", pkg.Version)
		note(c, "  created     %s", pkg.Created)
		note(c, "  seal        %s  (%s, signed=%t)", pkg.Seal.Digest, pkg.Seal.Algorithm, pkg.Seal.Signed)
		note(c, "  components  %d", len(pkg.Components))
		note(c, "  images      %v", pkg.Manifest.Images)
		note(c, "  workloads   %v", pkg.Manifest.Workloads)
		note(c, "\n  next:  caisson sbom view %s   ·   caisson evidence export %s", path, path)
		note(c, "\n[scaffold] placeholder output — real unpacking lives in internal/pkgformat")
		return nil
	},
}

func init() {
	packageCmd.AddCommand(packageCreateCmd, packageInspectCmd, packageDeployCmd)
}
