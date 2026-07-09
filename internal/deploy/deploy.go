// Package deploy carries a sealed vault across the airgap. Today it performs a
// real seal verification (delegating to pkgformat.Verify); pushing images to an
// OCI registry and applying workloads to Kubernetes are described by the CLI but
// not yet executed. Caisson wraps the registry and cluster you already run
// rather than reimplementing image transfer or Kubernetes.
package deploy

import "github.com/optimal-cyber/caisson/internal/pkgformat"

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

// VerifySeal opens the vault and checks that its payload matches the sealed
// manifest digest before anything is applied. This is a real integrity check.
func VerifySeal(path string) (bool, *pkgformat.Manifest, error) {
	return pkgformat.Verify(path)
}
