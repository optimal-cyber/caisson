package cmd

import (
	"fmt"

	"github.com/optimal-cyber/caisson/internal/deploy"
	"github.com/spf13/cobra"
)

var evidenceExport bool

// deployCmd is the top-level convenience form: `caisson deploy my-app.caisson`.
// It shares its behavior with `caisson package deploy`.
var deployCmd = &cobra.Command{
	Use:   "deploy [package]",
	Short: "Carry a sealed vault across the airgap and apply it",
	Long: `Deploy a sealed vault into denied territory.

Real today: opens the vault and verifies the payload digest against the sealed
manifest (a tamper check) before doing anything. Not yet implemented: pushing
images to an OCI registry and applying workloads to Kubernetes are described but
not executed. Caisson wraps the registry and cluster you already run.`,
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

	ok, m, err := deploy.VerifySeal(path)
	if err != nil {
		return err
	}

	// Heuristic: treat sealed *.yaml/*.yml as Kubernetes workloads to apply.
	var workloads []string
	for _, f := range m.Files {
		if f.Type == "k8s-manifest" {
			workloads = append(workloads, f.Path)
		}
	}
	target := deploy.DefaultTarget()

	note(c, "deploy: %s → %s / %s\n", path, target.Cluster, target.Namespace)
	if !ok {
		note(c, "  ✗ SEAL BROKEN · payload digest does NOT match manifest — refusing to deploy")
		return fmt.Errorf("deploy: seal verification failed for %s", path)
	}
	note(c, "  ✓ seal verified · payload digest matches manifest")
	note(c, "    %s", m.Digest)
	note(c, "  · found %d kubernetes manifest(s) in payload", len(workloads))
	for _, w := range workloads {
		note(c, "      - %s", w)
	}
	note(c, "\n  [not implemented] would push images to %s", target.Registry)
	note(c, "  [not implemented] would apply %d workload(s) to cluster %q", len(workloads), target.Cluster)
	if evidenceExport {
		note(c, "  [not implemented] would export the evidence bundle on arrival")
	}
	return nil
}

func init() {
	deployCmd.Flags().BoolVar(&evidenceExport, "evidence-export", false, "export the assessment evidence bundle on arrival")
	packageDeployCmd.Flags().BoolVar(&evidenceExport, "evidence-export", false, "export the assessment evidence bundle on arrival")
}
