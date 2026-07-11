// Package deploy carries a sealed vault across the airgap and, on the far side,
// pushes its images to a registry and applies its workloads to Kubernetes.
//
// VerifySeal is a real integrity check (delegating to pkgformat.Verify) and
// always runs first. PushImages and ApplyWorkloads are the real delivery paths:
// they need a reachable registry and a Kubernetes cluster with credentials, so
// they are guarded behind an explicit --apply and wrap the tools you already run
// (go-containerregistry for the push, kubectl for the apply) rather than
// reimplementing image transfer or Kubernetes.
package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/optimal-cyber/caisson/internal/oci"
	"github.com/optimal-cyber/caisson/internal/pkgformat"
)

// Target describes where a vault is delivered on the disconnected side.
type Target struct {
	Registry  string
	Cluster   string
	Namespace string
}

// DefaultTarget is a representative disconnected-side target for the scaffold.
func DefaultTarget() Target {
	return Target{
		Registry:  "registry.airgap.local:5000",
		Cluster:   "enclave-prod",
		Namespace: "default",
	}
}

// VerifySeal opens the vault and checks that its payload (and any embedded image
// layout) matches the sealed manifest digest before anything is applied. This is
// a real integrity check.
func VerifySeal(path string) (bool, *pkgformat.Manifest, error) {
	return pkgformat.Verify(path)
}

// PushImages extracts the vault's sealed OCI layout and pushes every image to
// targetRegistry, rewriting each image's registry host. It needs registry
// access and credentials. It returns an error (before any network I/O) if the
// vault carries no sealed image layout — pull the images at create time with
// --pull-images first.
func PushImages(vaultPath, targetRegistry string) ([]oci.Pushed, error) {
	tmp, err := os.MkdirTemp("", "caisson-push-oci-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	found, err := pkgformat.ExtractImageLayout(vaultPath, tmp)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("deploy: no sealed image layout in %s — re-create it with --pull-images before pushing", vaultPath)
	}
	return oci.PushLayout(tmp, targetRegistry)
}

// ApplyOptions configures a real Kubernetes apply.
type ApplyOptions struct {
	Namespace   string
	KubeContext string
	Kubectl     string // kubectl binary; defaults to "kubectl"
	Helm        string // helm binary; defaults to "helm"
}

// ApplyChart extracts the sealed Helm chart at chartPath from the vault and runs
// `helm upgrade --install release <chart>`. It needs helm on PATH and a reachable
// cluster with credentials. It returns helm's combined output.
func ApplyChart(vaultPath, chartPath, release string, opts ApplyOptions) (string, error) {
	helm := opts.Helm
	if helm == "" {
		helm = "helm"
	}
	bin, err := exec.LookPath(helm)
	if err != nil {
		return "", fmt.Errorf("deploy: %q not found on PATH (needed to apply the Helm chart): %w", helm, err)
	}

	tmp, err := os.MkdirTemp("", "caisson-helm-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	n, err := pkgformat.ExtractPayloadTree(vaultPath, tmp, chartPath)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("deploy: Helm chart %q not found in the vault payload", chartPath)
	}
	chartDir := filepath.Join(tmp, filepath.FromSlash(chartPath))

	args := []string{"upgrade", "--install", release, chartDir}
	if opts.Namespace != "" {
		args = append(args, "-n", opts.Namespace, "--create-namespace")
	}
	if opts.KubeContext != "" {
		args = append(args, "--kube-context", opts.KubeContext)
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("deploy: helm upgrade --install failed: %w", err)
	}
	return string(out), nil
}

// ApplyWorkloads extracts the named manifests from the vault payload and applies
// them with kubectl. It needs kubectl on PATH and a reachable cluster with
// credentials. It returns kubectl's combined output.
func ApplyWorkloads(vaultPath string, workloads []string, opts ApplyOptions) (string, error) {
	if len(workloads) == 0 {
		return "", nil
	}
	kubectl := opts.Kubectl
	if kubectl == "" {
		kubectl = "kubectl"
	}
	bin, err := exec.LookPath(kubectl)
	if err != nil {
		return "", fmt.Errorf("deploy: %q not found on PATH (needed to apply workloads): %w", kubectl, err)
	}

	tmp, err := os.MkdirTemp("", "caisson-apply-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	files, err := pkgformat.ExtractPayloadFiles(vaultPath, tmp, workloads)
	if err != nil {
		return "", err
	}

	args := []string{"apply"}
	if opts.KubeContext != "" {
		args = append(args, "--context", opts.KubeContext)
	}
	if opts.Namespace != "" {
		args = append(args, "-n", opts.Namespace)
	}
	for _, f := range files {
		args = append(args, "-f", f)
	}

	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("deploy: kubectl apply failed: %w", err)
	}
	return string(out), nil
}
