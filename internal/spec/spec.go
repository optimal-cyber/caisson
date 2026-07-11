// Package spec parses and writes caisson.yaml — the declarative package
// definition for a Caisson project. It describes what to seal (name, version,
// source tree, container images, Kubernetes manifests), which compliance
// frameworks the sealed evidence is asserted to map to, and the signing
// identity that binds provenance.
//
// `caisson init` writes a caisson.yaml; `caisson package create` reads it when
// present, with command-line flags overriding individual fields. Paths inside
// the file (source, manifests, signing key) are resolved relative to the
// caisson.yaml's own directory, so a spec is portable regardless of the working
// directory it is invoked from.
package spec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the canonical caisson.yaml filename looked up in a project root.
const FileName = "caisson.yaml"

// Signing describes how the vault is signed.
type Signing struct {
	// Key is a path to an Ed25519 private key (PEM). A relative path is
	// resolved against the caisson.yaml's directory.
	Key string `yaml:"key,omitempty"`
}

// Helm declares a Helm chart carried in the source, applied with `helm upgrade
// --install` on the disconnected side instead of raw kubectl manifests.
type Helm struct {
	// Chart is a path (relative to source) to the chart directory, sealed in
	// the vault's payload.
	Chart string `yaml:"chart,omitempty"`
	// Release is the Helm release name; defaults to the package name.
	Release string `yaml:"release,omitempty"`
}

// Spec is a parsed caisson.yaml.
type Spec struct {
	Name       string   `yaml:"name"`
	Version    string   `yaml:"version"`
	Source     string   `yaml:"source"`
	Images     []string `yaml:"images,omitempty"`
	Manifests  []string `yaml:"manifests,omitempty"`
	Frameworks []string `yaml:"frameworks,omitempty"`
	Signing    Signing  `yaml:"signing,omitempty"`
	Helm       Helm     `yaml:"helm,omitempty"`

	// dir is the directory the spec was loaded from; relative paths resolve
	// against it. Set by Load/LoadFile, not by YAML.
	dir string `yaml:"-"`
}

// Load looks for a caisson.yaml in dir and parses it. The bool reports whether
// a file was found; a missing file is not an error (Load returns nil, false,
// nil) so callers can fall back to flags.
func Load(dir string) (*Spec, bool, error) {
	path := filepath.Join(dir, FileName)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	s, err := LoadFile(path)
	if err != nil {
		return nil, false, err
	}
	return s, true, nil
}

// LoadFile parses the caisson.yaml at path.
func LoadFile(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.dir = filepath.Dir(path)
	return s, nil
}

// Parse decodes and validates caisson.yaml bytes.
func Parse(data []byte) (*Spec, error) {
	var s Spec
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("caisson.yaml: %w", err)
	}
	s.normalize()
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// normalize trims whitespace and drops empty list entries.
func (s *Spec) normalize() {
	s.Name = strings.TrimSpace(s.Name)
	s.Version = strings.TrimSpace(s.Version)
	s.Source = strings.TrimSpace(s.Source)
	s.Signing.Key = strings.TrimSpace(s.Signing.Key)
	s.Images = trimList(s.Images)
	s.Manifests = trimList(s.Manifests)
	s.Frameworks = trimList(s.Frameworks)
}

// Validate reports whether the spec carries enough to identify a package.
func (s *Spec) Validate() error {
	if s.Name == "" && s.Source == "" {
		return errors.New("caisson.yaml: needs at least a name or a source")
	}
	return nil
}

// Dir returns the directory the spec was loaded from (empty for a spec built
// in memory). Relative paths are resolved against it.
func (s *Spec) Dir() string { return s.dir }

// ResolvedSource returns the source directory to seal, resolved against the
// spec's directory. It defaults to the spec directory itself when source is
// unset.
func (s *Spec) ResolvedSource() string {
	return s.resolve(orDefault(s.Source, "."))
}

// ResolvedKey returns the signing key path resolved against the spec's
// directory, or "" when no key is declared.
func (s *Spec) ResolvedKey() string {
	if s.Signing.Key == "" {
		return ""
	}
	return s.resolve(s.Signing.Key)
}

// resolve joins a spec-relative path against the spec's directory. Absolute
// paths are returned unchanged.
func (s *Spec) resolve(p string) string {
	if p == "" || filepath.IsAbs(p) || s.dir == "" {
		return p
	}
	return filepath.Join(s.dir, p)
}

func trimList(in []string) []string {
	out := in[:0]
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
