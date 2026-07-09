package cmd

import (
	"github.com/optimal-cyber/caisson/internal/deploy"
	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/spf13/cobra"
)

var evidenceExport bool

// deployCmd is the top-level convenience form: `caisson deploy my-app.caisson`.
// It shares its behavior with `caisson package deploy`.
var deployCmd = &cobra.Command{
	Use:   "deploy [package]",
	Short: "Carry a sealed vault across the airgap and apply it",
	Long: `Deploy a sealed vault into denied territory.

Verifies the seal and provenance on arrival, pushes images to the disconnected
OCI registry, applies workloads to Kubernetes, and — with --evidence-export —
emits the assessment-ready evidence bundle alongside the deploy.

Caisson wraps the registry and cluster you already run; it does not replace them.`,
	Args: cobra.ExactArgs(1),
	RunE: runDeploy,
}

// packageDeployCmd is the canonical form under the `package` group.
var packageDeployCmd = &cobra.Command{
	Use:   "deploy [package]",
	Short: "Carry a sealed vault across the airgap and apply it",
	Long:  deployCmd.Long,
	Args:  cobra.ExactArgs(1),
	RunE:  runDeploy,
}

func runDeploy(c *cobra.Command, args []string) error {
	path := args[0]

	pkg, err := pkgformat.Inspect(path)
	if err != nil {
		return err
	}
	ok, err := deploy.VerifySeal(path)
	if err != nil {
		return err
	}

	target := deploy.DefaultTarget()
	plan := deploy.NewPlan(pkg.Manifest.Images, pkg.Manifest.Workloads, target)
	res, err := plan.Apply(evidenceExport)
	if err != nil {
		return err
	}

	note(c, "deploy: %s → %s / %s\n", path, target.Cluster, target.Namespace)
	note(c, "  ✓ seal verified: %t · provenance intact: %t", ok && res.SealVerified, res.ProvenanceIntact)
	note(c, "  ✓ pushed %d images to %s", res.ImagesPushed, target.Registry)
	note(c, "  ✓ applied %d workloads to cluster %q", res.WorkloadsApplied, target.Cluster)
	if evidenceExport {
		note(c, "  ✓ evidence bundle exported → %s/", res.EvidencePath)
	} else {
		note(c, "  · evidence export skipped (pass --evidence-export to emit on arrival)")
	}
	note(c, "\n[scaffold] placeholder output — real deploy lives in internal/deploy")
	return nil
}

func init() {
	deployCmd.Flags().BoolVar(&evidenceExport, "evidence-export", false, "export the assessment evidence bundle on arrival")
	packageDeployCmd.Flags().BoolVar(&evidenceExport, "evidence-export", false, "export the assessment evidence bundle on arrival")
}
