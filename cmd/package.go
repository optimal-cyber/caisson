package cmd

import (
	"os"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/optimal-cyber/caisson/internal/signing"
	"github.com/spf13/cobra"
)

var packageCmd = &cobra.Command{
	Use:     "package",
	Aliases: []string{"pkg"},
	Short:   "Create and inspect sealed Caisson vaults",
	Long:    "Work with the .caisson vault: seal a source tree into one, or inspect what a sealed vault carries.",
}

var (
	createName    string
	createVersion string
	createKey     string
)

var packageCreateCmd = &cobra.Command{
	Use:   "create [source]",
	Short: "Seal a source directory into a .caisson vault",
	Long: `Seal a directory into a Caisson vault.

Packs the source tree into a gzip-compressed .caisson archive with a manifest
recording a per-file SHA-256 inventory and an overall content digest. This is a
real operation: it writes a vault to disk you can inspect and verify.

Not yet implemented: cosign signing and a full dependency SBOM — for now the
inventory is file-level.`,
	Args: cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		src := args[0]

		var signer *signing.Key
		if createKey != "" {
			pemBytes, err := os.ReadFile(createKey)
			if err != nil {
				return err
			}
			signer, err = signing.LoadPrivate(pemBytes)
			if err != nil {
				return err
			}
		}

		m, out, err := pkgformat.Create(src, pkgformat.CreateOptions{
			Name:    createName,
			Version: createVersion,
			Signer:  signer,
		})
		if err != nil {
			return err
		}
		note(c, "package create: sealed %q\n", src)
		note(c, "  ✓ packed %d files · %s", m.FileCount, humanSize(m.TotalSize))
		note(c, "  ✓ per-file SHA-256 recorded · content digest computed")
		note(c, "  ✓ manifest sealed (format %s)", m.FormatVersion)
		if m.Signed {
			note(c, "  ✓ signed (ed25519, keyId %s) · SLSA provenance attested", short(signer.KeyID()))
		} else {
			note(c, "  · unsigned (pass --key <caisson.key> to sign + attest)")
		}
		note(c, "\n  vault → %s   (%s v%s)", out, m.Name, m.Version)
		note(c, "  digest  %s", m.Digest)
		if m.Signed {
			note(c, "\n  next:  caisson verify %s --key <public.pem>", out)
		} else {
			note(c, "\n  next:  caisson package inspect %s", out)
		}
		return nil
	},
}

var packageInspectCmd = &cobra.Command{
	Use:   "inspect [package]",
	Short: "Show what a sealed vault carries, without deploying it",
	Long:  "Open a .caisson vault and print its manifest — read-only, nothing is extracted or applied.",
	Args:  cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		m, err := pkgformat.Open(path)
		if err != nil {
			return err
		}
		note(c, "package inspect: %s\n", path)
		note(c, "  name        %s", m.Name)
		note(c, "  version     %s", m.Version)
		note(c, "  created     %s", m.Created)
		note(c, "  format      %s", m.FormatVersion)
		note(c, "  source      %s", m.Source)
		note(c, "  files       %d · %s", m.FileCount, humanSize(m.TotalSize))
		note(c, "  signed      %t", m.Signed)
		note(c, "  digest      %s", m.Digest)
		note(c, "\n  next:  caisson sbom view %s   ·   caisson evidence export %s", path, path)
		return nil
	},
}

func init() {
	packageCreateCmd.Flags().StringVar(&createName, "name", "", "package name (default: source directory name)")
	packageCreateCmd.Flags().StringVar(&createVersion, "version", "", "package version (default: 0.0.0)")
	packageCreateCmd.Flags().StringVar(&createKey, "key", "", "Ed25519 private key (PEM) to sign the vault and attest provenance")
	packageCmd.AddCommand(packageCreateCmd, packageInspectCmd, packageDeployCmd)
}
