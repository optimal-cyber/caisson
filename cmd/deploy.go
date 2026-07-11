package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/optimal-cyber/caisson/internal/deploy"
	"github.com/optimal-cyber/caisson/internal/evidence"
	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/optimal-cyber/caisson/internal/spec"
	"github.com/optimal-cyber/caisson/internal/vuln"
	"github.com/spf13/cobra"
)

var (
	evidenceExport    bool
	denySeverity      string
	requireSignature  bool
	applyDeploy       bool
	deployRegistry    string
	deployNamespace   string
	deployKubeContext string
	deployKubectl     string
)

// deployCmd is the top-level convenience form: `caisson deploy my-app.caisson`.
// It shares its behavior with `caisson package deploy`.
var deployCmd = &cobra.Command{
	Use:   "deploy [package]",
	Short: "Carry a sealed vault across the airgap and apply it",
	Long: `Deploy a sealed vault into denied territory.

Always verifies the seal (payload + embedded image layout) and signature and runs
the policy gate first; a tampered, badly-signed, or policy-violating vault is
refused before anything is delivered. Without --apply it prints the delivery
plan. With --apply it executes the delivery: pushes the sealed images to the
target registry (go-containerregistry) and applies the workloads with kubectl —
which needs a reachable registry and cluster with credentials. Caisson wraps the
registry and cluster you already run rather than replacing them.`,
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
	sr, err := pkgformat.VerifySignature(path, nil)
	if err != nil {
		return err
	}

	// Prefer the workloads the caisson.yaml declared; otherwise fall back to
	// treating sealed *.yaml/*.yml as Kubernetes manifests (excluding the
	// caisson.yaml itself, which is project config, not a workload).
	var workloads []string
	if len(m.Workloads) > 0 {
		workloads = m.Workloads
	} else {
		for _, f := range m.Files {
			if f.Type == "k8s-manifest" && f.Path != spec.FileName {
				workloads = append(workloads, f.Path)
			}
		}
	}
	target := deploy.DefaultTarget()
	if deployRegistry != "" {
		target.Registry = deployRegistry
	}
	if deployNamespace != "" {
		target.Namespace = deployNamespace
	}

	note(c, "deploy: %s → %s / %s\n", path, target.Cluster, target.Namespace)
	if !ok {
		note(c, "  ✗ SEAL BROKEN · payload digest does NOT match manifest — refusing to deploy")
		return fmt.Errorf("deploy: seal verification failed for %s", path)
	}
	note(c, "  ✓ seal verified · payload digest matches manifest")
	note(c, "    %s", m.Digest)
	switch {
	case !sr.Present:
		note(c, "  · unsigned vault (no signature to verify)")
	case sr.Valid:
		note(c, "  ✓ signature verified (keyId %s)%s", short(sr.KeyID), provNote(sr))
	default:
		note(c, "  ✗ SIGNATURE INVALID — refusing to deploy")
		return fmt.Errorf("deploy: signature verification failed for %s", path)
	}
	if m.Scan != nil {
		note(c, "  · vulnerability scan (%s): %d findings [%s]", m.Scan.Source, m.Scan.Total, joinComma(scanSummary(m.Scan.Counts)))
	}

	// Policy gate: refuse the deploy if declared policy is not met.
	if fail := policyGate(c, m, sr); fail != nil {
		return fail
	}
	note(c, "  · found %d kubernetes manifest(s) in payload", len(workloads))
	for _, w := range workloads {
		note(c, "      - %s", w)
	}
	var pulled, declared []string
	for _, img := range m.Images {
		if img.Pulled {
			pulled = append(pulled, img.Reference)
		} else {
			declared = append(declared, img.Reference)
		}
	}
	if len(pulled) > 0 {
		note(c, "  · %d image(s) sealed in the vault's OCI layout (verified with the seal)", len(pulled))
	}
	if len(declared) > 0 {
		note(c, "  · %d image(s) declared but not sealed (re-create with --pull-images to deliver them)", len(declared))
	}

	if !applyDeploy {
		note(c, "\n  dry run — pass --apply to execute (needs a reachable registry + cluster):")
		if len(pulled) > 0 {
			note(c, "  · would push %d image(s) to %s", len(pulled), target.Registry)
		}
		note(c, "  · would apply %d workload(s) to %s/%s via kubectl", len(workloads), target.Cluster, target.Namespace)
		if evidenceExport {
			note(c, "  · would export the evidence bundle on arrival")
		}
		return nil
	}

	// --apply: real delivery. The seal, signature, and policy gate above have
	// already passed, so we only reach here for a vault cleared to land.
	note(c, "\n  --apply: delivering (needs registry + cluster access)…")
	if err := applyDelivery(c, path, m, target, pulled, declared, workloads); err != nil {
		return err
	}
	return nil
}

// applyDelivery performs the real, guarded delivery: push the sealed images to
// the target registry, apply the workloads with kubectl, and (optionally) write
// the evidence bundle on arrival.
func applyDelivery(c *cobra.Command, path string, m *pkgformat.Manifest, target deploy.Target, pulled, declared, workloads []string) error {
	switch {
	case len(pulled) > 0:
		pushed, err := deploy.PushImages(path, target.Registry)
		if err != nil {
			return err
		}
		for _, p := range pushed {
			note(c, "  ✓ pushed %s → %s", p.From, p.To)
		}
	case len(declared) > 0:
		note(c, "  · skipping image push — images are declared-only (re-create with --pull-images)")
	}

	if len(workloads) > 0 {
		out, err := deploy.ApplyWorkloads(path, workloads, deploy.ApplyOptions{
			Namespace:   target.Namespace,
			KubeContext: deployKubeContext,
			Kubectl:     deployKubectl,
		})
		for _, line := range splitLines(out) {
			note(c, "      %s", line)
		}
		if err != nil {
			return err
		}
		note(c, "  ✓ applied %d workload(s) to namespace %q via kubectl", len(workloads), target.Namespace)
	}

	if evidenceExport {
		bundle := evidence.Collect(m, time.Now().UTC())
		written, err := evidence.Export(bundle, "./evidence")
		if err != nil {
			return err
		}
		note(c, "  ✓ exported evidence bundle on arrival (%d files under ./evidence)", len(written))
	}
	return nil
}

// splitLines splits kubectl output into non-empty display lines.
func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// policyGate enforces --require-signature and --deny-severity. It returns a
// non-nil error (which aborts the deploy) when the vault violates policy.
func policyGate(c *cobra.Command, m *pkgformat.Manifest, sr *pkgformat.SignatureResult) error {
	if denySeverity == "" && !requireSignature {
		return nil
	}
	var violations []string
	if requireSignature && (!sr.Present || !sr.Valid) {
		violations = append(violations, "vault is unsigned or the signature is invalid (--require-signature)")
	}
	if denySeverity != "" {
		min := vuln.ParseSeverity(denySeverity)
		if m.Scan == nil {
			violations = append(violations, fmt.Sprintf("no vulnerability scan attached; cannot evaluate --deny-severity %s (fail-closed)", denySeverity))
		} else if n := vuln.CountAtLeastIn(m.Scan.Counts, min); n > 0 {
			violations = append(violations, fmt.Sprintf("%d finding(s) at or above %q (--deny-severity)", n, min))
		}
	}
	if len(violations) > 0 {
		note(c, "\n  ✗ POLICY GATE FAILED — refusing to deploy:")
		for _, v := range violations {
			note(c, "      - %s", v)
		}
		return fmt.Errorf("deploy: policy gate failed for %s", m.Filename())
	}
	note(c, "  ✓ policy gate passed")
	return nil
}

func provNote(sr *pkgformat.SignatureResult) string {
	var parts []string
	if sr.ProvenancePresent {
		if sr.ProvenanceValid {
			parts = append(parts, "SLSA provenance valid")
		} else {
			parts = append(parts, "SLSA provenance INVALID")
		}
	}
	if sr.SBOMAttestationPresent {
		if sr.SBOMAttestationValid {
			parts = append(parts, "SBOM attestation valid")
		} else {
			parts = append(parts, "SBOM attestation INVALID")
		}
	}
	if sr.VulnAttestationPresent {
		if sr.VulnAttestationValid {
			parts = append(parts, "vuln attestation valid")
		} else {
			parts = append(parts, "vuln attestation INVALID")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " · " + joinComma(parts)
}

func init() {
	for _, cmd := range []*cobra.Command{deployCmd, packageDeployCmd} {
		cmd.Flags().BoolVar(&evidenceExport, "evidence-export", false, "export the assessment evidence bundle on arrival")
		cmd.Flags().StringVar(&denySeverity, "deny-severity", "", "refuse deploy if the scan has findings at/above this severity (critical|high|medium|low)")
		cmd.Flags().BoolVar(&requireSignature, "require-signature", false, "refuse deploy unless the vault is validly signed")
		cmd.Flags().BoolVar(&applyDeploy, "apply", false, "execute the delivery: push images to the registry and apply workloads with kubectl (needs registry + cluster access)")
		cmd.Flags().StringVar(&deployRegistry, "registry", "", "target registry to push sealed images to (default: the scaffold target)")
		cmd.Flags().StringVar(&deployNamespace, "namespace", "", "Kubernetes namespace to apply workloads into")
		cmd.Flags().StringVar(&deployKubeContext, "kube-context", "", "kubectl context to apply workloads with")
		cmd.Flags().StringVar(&deployKubectl, "kubectl", "kubectl", "kubectl binary to invoke")
	}
}
