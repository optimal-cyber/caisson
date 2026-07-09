// Package pkgformat defines the on-disk ".caisson" package format: the sealed,
// hexagonal "vault" that carries an application together with its SBOM,
// compliance evidence, and cryptographic provenance across the airgap.
//
// Scaffold status: the exported types describe the real format and the
// constructors return representative placeholder data. Replace the bodies with
// real packing/unpacking, digesting, and signing — the signatures are meant to
// stay stable.
package pkgformat

import "errors"

// Extension is the file suffix for a sealed Caisson vault.
const Extension = ".caisson"

// ErrNotImplemented marks scaffold code paths that still need real behavior.
var ErrNotImplemented = errors.New("pkgformat: not yet implemented (scaffold stub)")

// Component is one item in the package's software bill of materials.
type Component struct {
	Name    string
	Version string
	Type    string // e.g. "container-image", "go-module", "rpm"
	PURL    string // package URL (purl) identity
	License string
}

// Manifest lists the deployable contents carried by the vault.
type Manifest struct {
	Images    []string
	Workloads []string
}

// Seal is the cryptographic provenance binding the vault to its build.
type Seal struct {
	Algorithm string
	Digest    string
	Signer    string
	Signed    bool
}

// Package is the in-memory view of a Caisson vault.
type Package struct {
	Name       string
	Version    string
	Created    string // RFC3339; real impl stamps the build time
	Source     string
	Components []Component
	Manifest   Manifest
	Seal       Seal
}

// Filename returns the canonical vault filename for this package.
func (p *Package) Filename() string { return p.Name + Extension }

// Create seals a source directory into a Caisson vault.
//
// Real implementation: resolve dependencies, build the SBOM, capture images and
// workloads, compute digests, and sign the seal. Scaffold: returns placeholder
// data describing what a real create would produce.
func Create(source string) (*Package, error) {
	return sample(source), nil
}

// Inspect opens a sealed vault and returns its metadata without deploying it.
// Scaffold: returns placeholder data.
func Inspect(path string) (*Package, error) {
	return sample(path), nil
}

func sample(source string) *Package {
	return &Package{
		Name:    "my-app",
		Version: "1.4.2",
		Created: "2026-01-15T09:30:00Z",
		Source:  source,
		Components: []Component{
			{Name: "my-app", Version: "1.4.2", Type: "container-image", PURL: "pkg:oci/my-app@sha256:9f2c…", License: "Apache-2.0"},
			{Name: "nginx", Version: "1.27.3", Type: "container-image", PURL: "pkg:oci/nginx@1.27.3", License: "BSD-2-Clause"},
			{Name: "golang.org/x/crypto", Version: "0.31.0", Type: "go-module", PURL: "pkg:golang/golang.org/x/crypto@0.31.0", License: "BSD-3-Clause"},
			{Name: "openssl-libs", Version: "3.2.2", Type: "rpm", PURL: "pkg:rpm/openssl-libs@3.2.2", License: "Apache-2.0"},
		},
		Manifest: Manifest{
			Images:    []string{"my-app:1.4.2", "nginx:1.27.3"},
			Workloads: []string{"Deployment/my-app", "Service/my-app", "ConfigMap/my-app-config"},
		},
		Seal: Seal{
			Algorithm: "cosign/ecdsa-p256",
			Digest:    "sha256:9f2c7a…placeholder",
			Signer:    "buildhost@program.mil",
			Signed:    true,
		},
	}
}
