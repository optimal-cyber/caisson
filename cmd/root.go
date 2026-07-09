package cmd

import (
	"fmt"
	"os"

	"github.com/optimal-cyber/caisson/internal/brand"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "caisson",
	Short:   brand.Tagline,
	Version: brand.Version,
	Long: `Caisson seals an application together with its SBOM attestations,
NIST 800-53 / CMMC control evidence, and cryptographic provenance into a single
portable vault, carries it across the airgap, and verifies the seal on arrival —
so what lands in the disconnected environment is signed and assessment-ready.

Caisson is complementary to existing airgap tooling: it wraps the OCI registries
and Kubernetes clusters you already run rather than replacing them.`,
	// With no subcommand, show the vault and the map.
	Run: func(c *cobra.Command, args []string) {
		fmt.Fprintln(c.OutOrStdout(), brand.Banner())
		_ = c.Help()
		fmt.Fprintf(c.OutOrStdout(), "\n  %s\n", brand.CLITag)
	},
	SilenceUsage: true,
}

// Execute runs the root command. Called by main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "caisson:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetVersionTemplate("caisson {{.Version}}\n")
	rootCmd.AddCommand(initCmd, packageCmd, sbomCmd, evidenceCmd, deployCmd)
}

// note is a small shared helper for the scaffold's "not wired up yet" line.
func note(c *cobra.Command, format string, a ...any) {
	fmt.Fprintf(c.OutOrStdout(), format+"\n", a...)
}
