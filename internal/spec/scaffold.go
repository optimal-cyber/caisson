package spec

import (
	"fmt"
	"strings"
)

// DefaultFrameworks are the compliance frameworks a new project maps to unless
// the scaffold is told otherwise.
var DefaultFrameworks = []string{
	"NIST SP 800-53 Rev 5",
	"CMMC 2.0 Level 2",
}

// ScaffoldOptions configures the caisson.yaml that Scaffold renders.
type ScaffoldOptions struct {
	Name       string   // package name (required)
	Version    string   // defaults to "0.1.0"
	Source     string   // source tree to seal; defaults to "."
	Frameworks []string // defaults to DefaultFrameworks
}

// Scaffold renders a starter caisson.yaml (with explanatory comments) for a
// project. The output parses cleanly back through Parse.
func Scaffold(opts ScaffoldOptions) []byte {
	name := orDefault(strings.TrimSpace(opts.Name), "my-app")
	version := orDefault(strings.TrimSpace(opts.Version), "0.1.0")
	source := orDefault(strings.TrimSpace(opts.Source), ".")
	frameworks := opts.Frameworks
	if len(frameworks) == 0 {
		frameworks = DefaultFrameworks
	}

	var b strings.Builder
	b.WriteString("# caisson.yaml — declarative package definition for a Caisson vault.\n")
	b.WriteString("# `caisson package create` reads this file; command-line flags override it.\n\n")

	fmt.Fprintf(&b, "name: %s\n", name)
	fmt.Fprintf(&b, "version: %s\n\n", version)

	b.WriteString("# Directory sealed into the vault (relative to this file).\n")
	fmt.Fprintf(&b, "source: %s\n\n", source)

	b.WriteString("# Container images the workload references. Declared here now; pulled into\n")
	b.WriteString("# an OCI layout inside the vault when image support is run with registry access.\n")
	b.WriteString("images:\n")
	fmt.Fprintf(&b, "  - registry.airgap.local:5000/%s:%s\n\n", name, version)

	b.WriteString("# Kubernetes manifests applied on the disconnected side (relative to source).\n")
	b.WriteString("manifests:\n")
	b.WriteString("  - k8s/deployment.yaml\n")
	b.WriteString("  - k8s/service.yaml\n\n")

	b.WriteString("# Compliance frameworks the sealed evidence is asserted to map to.\n")
	b.WriteString("frameworks:\n")
	for _, f := range frameworks {
		fmt.Fprintf(&b, "  - %s\n", f)
	}
	b.WriteString("\n")

	b.WriteString("# Signing identity. Generate a key with `caisson key gen --out caisson`,\n")
	b.WriteString("# then point `key` at the private PEM (kept out of version control).\n")
	b.WriteString("signing:\n")
	b.WriteString("  key: caisson.key\n")

	return []byte(b.String())
}
