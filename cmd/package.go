package cmd

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/optimal-cyber/caisson/internal/signing"
	"github.com/optimal-cyber/caisson/internal/spec"
	"github.com/optimal-cyber/caisson/internal/vuln"
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
	createScan    string
	createConfig  string
)

var packageCreateCmd = &cobra.Command{
	Use:   "create [source]",
	Short: "Seal a source directory into a .caisson vault",
	Long: `Seal a directory into a Caisson vault.

Packs the source tree into a gzip-compressed .caisson archive with a manifest
recording a per-file SHA-256 inventory and an overall content digest. This is a
real operation: it writes a vault to disk you can inspect and verify.

When a caisson.yaml is present (in the source directory, the working directory,
or passed via --config) its name, version, source, images, manifests,
frameworks, and signing key are used as defaults. Command-line flags override
individual fields.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPackageCreate,
}

func runPackageCreate(c *cobra.Command, args []string) error {
	sp, specPath, err := resolveSpec(args)
	if err != nil {
		return err
	}

	// Effective settings: the spec supplies defaults, flags override.
	name, version, keyPath := createName, createVersion, createKey
	var frameworks, images, workloads []string
	if sp != nil {
		if name == "" {
			name = sp.Name
		}
		if version == "" {
			version = sp.Version
		}
		if keyPath == "" {
			keyPath = sp.ResolvedKey()
		}
		frameworks, images, workloads = sp.Frameworks, sp.Images, sp.Manifests
	}

	// Source: a positional arg wins, then the spec's source, else it's an error.
	var src string
	switch {
	case len(args) > 0:
		src = args[0]
	case sp != nil:
		src = sp.ResolvedSource()
	default:
		return errors.New("package create: no source given — pass a directory or add a caisson.yaml (see `caisson init`)")
	}

	var signer *signing.Key
	if keyPath != "" {
		pemBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		signer, err = signing.LoadPrivate(pemBytes)
		if err != nil {
			return err
		}
	}

	var scan *vuln.Report
	if createScan != "" {
		data, err := os.ReadFile(createScan)
		if err != nil {
			return err
		}
		scan, err = vuln.Parse(data)
		if err != nil {
			return err
		}
	}

	m, out, err := pkgformat.Create(src, pkgformat.CreateOptions{
		Name:       name,
		Version:    version,
		Signer:     signer,
		Scan:       scan,
		Frameworks: frameworks,
		Images:     images,
		Workloads:  workloads,
	})
	if err != nil {
		return err
	}
	note(c, "package create: sealed %q\n", src)
	if specPath != "" {
		note(c, "  ✓ read %s", specPath)
	}
	note(c, "  ✓ packed %d files · %s", m.FileCount, humanSize(m.TotalSize))
	note(c, "  ✓ per-file SHA-256 recorded · content digest computed")
	if m.SBOM != nil {
		note(c, "  ✓ %s %s SBOM embedded (%d components)", m.SBOM.Format, m.SBOM.SpecVersion, m.SBOM.Components)
	}
	if m.Scan != nil {
		note(c, "  ✓ %s scan embedded (%d findings: %s)", m.Scan.Source, m.Scan.Total, joinComma(scanSummary(m.Scan.Counts)))
	}
	if len(m.Frameworks) > 0 {
		note(c, "  ✓ frameworks mapped: %s", joinComma(m.Frameworks))
	}
	if len(m.Images) > 0 {
		note(c, "  · %d image(s) declared — pulling into an OCI layout needs registry access", len(m.Images))
	}
	note(c, "  ✓ manifest sealed (format %s)", m.FormatVersion)
	if m.Signed {
		note(c, "  ✓ signed (ed25519, keyId %s) · SLSA provenance + CycloneDX SBOM attested", short(signer.KeyID()))
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
}

// resolveSpec locates the caisson.yaml governing this create, if any. An
// explicit --config wins; otherwise it looks in the project directory (the
// positional source arg when given, else the working directory). A missing
// caisson.yaml is not an error — create then relies entirely on flags.
func resolveSpec(args []string) (*spec.Spec, string, error) {
	if createConfig != "" {
		s, err := spec.LoadFile(createConfig)
		return s, createConfig, err
	}
	projectDir := "."
	if len(args) > 0 {
		projectDir = args[0]
	}
	s, found, err := spec.Load(projectDir)
	if err != nil || !found {
		return nil, "", err
	}
	return s, filepath.Join(projectDir, spec.FileName), nil
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
		if len(m.Frameworks) > 0 {
			note(c, "  frameworks  %s", joinComma(m.Frameworks))
		}
		for _, img := range m.Images {
			status := "declared"
			if img.Pulled {
				status = "pulled " + short(img.Digest)
			}
			note(c, "  image       %s (%s)", img.Reference, status)
		}
		note(c, "  digest      %s", m.Digest)
		note(c, "\n  next:  caisson sbom view %s   ·   caisson evidence export %s", path, path)
		return nil
	},
}

func init() {
	packageCreateCmd.Flags().StringVar(&createName, "name", "", "package name (default: source directory name)")
	packageCreateCmd.Flags().StringVar(&createVersion, "version", "", "package version (default: 0.0.0)")
	packageCreateCmd.Flags().StringVar(&createKey, "key", "", "Ed25519 private key (PEM) to sign the vault and attest provenance")
	packageCreateCmd.Flags().StringVar(&createScan, "scan-report", "", "Grype/Trivy JSON scan report to embed and attest")
	packageCreateCmd.Flags().StringVar(&createConfig, "config", "", "path to a caisson.yaml (default: caisson.yaml in the source or working directory)")
	packageCmd.AddCommand(packageCreateCmd, packageInspectCmd, packageDeployCmd)
}
