package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/optimal-cyber/caisson/internal/spec"
	"github.com/spf13/cobra"
)

var (
	initName    string
	initVersion string
	initSource  string
	initForce   bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold a caisson.yaml in the current project",
	Long: `Initialize a Caisson project.

Writes a caisson.yaml describing what to seal (source path, container images,
Kubernetes manifests), which compliance frameworks the sealed evidence maps to
(NIST 800-53, CMMC), and the signing identity to bind provenance. Run this once
at the root of the repo you intend to ship, then edit the file to taste.`,
	Args: cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := initName
		if name == "" {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			name = filepath.Base(wd)
		}

		path := spec.FileName
		if _, err := os.Stat(path); err == nil && !initForce {
			return fmt.Errorf("init: %s already exists (pass --force to overwrite)", path)
		}

		data := spec.Scaffold(spec.ScaffoldOptions{
			Name:    name,
			Version: initVersion,
			Source:  initSource,
		})
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}

		// Parse it back so init never leaves an unreadable file behind.
		s, err := spec.LoadFile(path)
		if err != nil {
			return fmt.Errorf("init: wrote %s but it did not parse: %w", path, err)
		}

		note(c, "init: wrote %s\n", path)
		note(c, "  package name  %s", s.Name)
		note(c, "  version       %s", s.Version)
		note(c, "  source        %s", s.Source)
		note(c, "  vault output  %s%s", s.Name, pkgformat.Extension)
		if len(s.Frameworks) > 0 {
			note(c, "  frameworks    %s", joinComma(s.Frameworks))
		}
		note(c, "  signing       %s (generate with `caisson key gen --out caisson`)", s.Signing.Key)
		note(c, "\n  next:  caisson package create   (reads %s)", path)
		return nil
	},
}

func init() {
	initCmd.Flags().StringVar(&initName, "name", "", "package name (default: current directory name)")
	initCmd.Flags().StringVar(&initVersion, "version", "", "package version (default: 0.1.0)")
	initCmd.Flags().StringVar(&initSource, "source", "", "source directory to seal (default: .)")
	initCmd.Flags().BoolVar(&initForce, "force", false, "overwrite an existing caisson.yaml")
}
