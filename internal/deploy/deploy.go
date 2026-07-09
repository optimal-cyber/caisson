// Package deploy carries a sealed vault across the airgap: it verifies the seal,
// pushes images to an OCI registry on the disconnected side, applies workloads
// to Kubernetes, and optionally exports evidence on arrival.
//
// Caisson deliberately wraps the OCI registries and clusters you already run —
// it does not reimplement image transfer or Kubernetes. Scaffold status: the
// types describe the real plan/result; Apply returns placeholder data.
package deploy

// Target describes where a vault is being delivered on the disconnected side.
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

// Plan is a resolved, reviewable deploy before anything is applied.
type Plan struct {
	Target    Target
	Images    []string
	Workloads []string
}

// NewPlan builds a deploy plan from a package's images and workloads.
func NewPlan(images, workloads []string, t Target) *Plan {
	return &Plan{Target: t, Images: images, Workloads: workloads}
}

// Result summarizes what a deploy did on the far side of the gap.
type Result struct {
	SealVerified     bool
	ProvenanceIntact bool
	ImagesPushed     int
	WorkloadsApplied int
	EvidencePath     string
}

// VerifySeal checks the vault's seal and provenance before any change is made.
// Scaffold: returns true.
func VerifySeal(path string) (bool, error) {
	return true, nil
}

// Apply executes the plan against the target. When exportEvidence is true it
// also emits the assessment bundle on arrival. Scaffold: returns placeholder
// counts describing what a real apply would do.
func (p *Plan) Apply(exportEvidence bool) (*Result, error) {
	res := &Result{
		SealVerified:     true,
		ProvenanceIntact: true,
		ImagesPushed:     len(p.Images),
		WorkloadsApplied: len(p.Workloads),
	}
	if exportEvidence {
		res.EvidencePath = "./evidence/" + p.Target.Namespace
	}
	return res, nil
}
