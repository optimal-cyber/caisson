// Package attest builds in-toto attestation statements about a Caisson vault.
// Statements are plain data here; the signing package wraps them in DSSE
// envelopes so they are cryptographically bound to the vault's signing key.
//
// Currently produces SLSA Provenance v1 (https://slsa.dev/provenance/v1). SBOM
// attestations are added alongside the real-SBOM milestone.
package attest

import "time"

// Statement and predicate type URIs.
const (
	StatementType     = "https://in-toto.io/Statement/v1"
	SLSAPredicateType = "https://slsa.dev/provenance/v1"

	// BuildType identifies how a Caisson vault is produced.
	BuildType = "https://caisson.gooptimal.io/buildtypes/package-create/v0.1"
	// BuilderID identifies the tool that produced the attestation.
	BuilderID = "https://caisson.gooptimal.io/caisson"
)

// Subject is one artifact an attestation is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto v1 statement wrapping a typed predicate.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     any       `json:"predicate"`
}

// ResourceDescriptor names a material/dependency by digest.
type ResourceDescriptor struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SLSAPredicate is a subset of the SLSA Provenance v1 predicate.
type SLSAPredicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]any       `json:"externalParameters"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

type RunDetails struct {
	Builder  Builder  `json:"builder"`
	Metadata Metadata `json:"metadata"`
}

type Builder struct {
	ID string `json:"id"`
}

type Metadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
}

// Provenance builds a SLSA provenance statement for a sealed vault. digestHex is
// the vault's content digest as bare hex (no "sha256:" prefix); materials are the
// payload files with their per-file SHA-256.
func Provenance(name, source, digestHex string, materials []ResourceDescriptor, builtAt time.Time) *Statement {
	return &Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name:   name + ".caisson",
			Digest: map[string]string{"sha256": digestHex},
		}},
		PredicateType: SLSAPredicateType,
		Predicate: SLSAPredicate{
			BuildDefinition: BuildDefinition{
				BuildType:            BuildType,
				ExternalParameters:   map[string]any{"source": source, "name": name},
				ResolvedDependencies: materials,
			},
			RunDetails: RunDetails{
				Builder:  Builder{ID: BuilderID},
				Metadata: Metadata{StartedOn: builtAt.UTC().Format(time.RFC3339)},
			},
		},
	}
}
