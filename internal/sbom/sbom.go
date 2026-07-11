// Package sbom generates a real CycloneDX 1.6 software bill of materials by
// scanning a vault's payload for dependency manifests — go.mod, package.json,
// requirements.txt, and Dockerfile base images. Standard-library only, so it
// runs disconnected.
//
// This is native manifest-detection, not full dependency resolution. Deeper
// analysis (transitive graphs, OS packages, licenses) via Syft is a documented
// follow-on; the output here is standard CycloneDX so that migration is clean.
package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Format and SpecVersion identify the emitted SBOM.
const (
	Format      = "CycloneDX"
	SpecVersion = "1.6"
)

// Component is one CycloneDX component.
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
}

type toolsWrap struct {
	Components []Component `json:"components"`
}

// Metadata is the CycloneDX metadata block.
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     toolsWrap `json:"tools"`
	Component Component `json:"component"`
}

// Document is a CycloneDX 1.6 BOM.
type Document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Generate scans dir for dependency manifests and builds a CycloneDX SBOM for an
// application named name@version.
func Generate(dir, name, version string, now time.Time) (*Document, error) {
	comps, err := scan(dir)
	if err != nil {
		return nil, err
	}
	comps = dedup(comps)

	return &Document{
		BOMFormat:    Format,
		SpecVersion:  SpecVersion,
		SerialNumber: "urn:uuid:" + detUUID(fmt.Sprintf("%s@%s:%d", name, version, len(comps))),
		Version:      1,
		Metadata: Metadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Tools:     toolsWrap{Components: []Component{{Type: "application", Name: "caisson", Version: "0.0.0-dev"}}},
			Component: Component{Type: "application", Name: name, Version: version, BOMRef: "app:" + name},
		},
		Components: comps,
	}, nil
}

// JSON renders the document as indented CycloneDX JSON.
func (d *Document) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func scan(dir string) ([]Component, error) {
	var comps []Component
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if e.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		base := e.Name()
		var found []Component
		switch {
		case base == "go.mod":
			found = parseGoMod(p)
		case base == "package.json":
			found = parsePackageJSON(p)
		case base == "requirements.txt":
			found = parseRequirements(p)
		case strings.EqualFold(base, "Dockerfile") || strings.HasSuffix(strings.ToLower(base), ".dockerfile"):
			found = parseDockerfile(p)
		}
		comps = append(comps, found...)
		return nil
	})
	return comps, err
}

func parseGoMod(path string) []Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var comps []Component
	inReq := false
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		switch {
		case l == "" || strings.HasPrefix(l, "//"):
			continue
		case strings.HasPrefix(l, "require ("):
			inReq = true
		case inReq && l == ")":
			inReq = false
		case inReq:
			comps = appendGoMod(comps, l)
		case strings.HasPrefix(l, "require "):
			comps = appendGoMod(comps, strings.TrimPrefix(l, "require "))
		}
	}
	return comps
}

func appendGoMod(comps []Component, spec string) []Component {
	if i := strings.Index(spec, "//"); i >= 0 {
		spec = spec[:i]
	}
	f := strings.Fields(spec)
	if len(f) < 2 {
		return comps
	}
	mod, ver := f[0], f[1]
	return append(comps, Component{Type: "library", Name: mod, Version: ver, PURL: "pkg:golang/" + mod + "@" + ver, BOMRef: "golang:" + mod + "@" + ver})
}

func parsePackageJSON(path string) []Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pj struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil
	}
	var comps []Component
	add := func(m map[string]string) {
		for name, ver := range m {
			v := strings.TrimLeft(ver, "^~>=<v ")
			comps = append(comps, Component{Type: "library", Name: name, Version: v, PURL: "pkg:npm/" + name + "@" + v, BOMRef: "npm:" + name + "@" + v})
		}
	}
	add(pj.Dependencies)
	add(pj.DevDependencies)
	return comps
}

func parseRequirements(path string) []Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var comps []Component
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "-") {
			continue
		}
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		name, ver := l, ""
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if i := strings.Index(l, sep); i >= 0 {
				name = strings.TrimSpace(l[:i])
				ver = strings.TrimSpace(l[i+len(sep):])
				break
			}
		}
		if i := strings.IndexAny(name, "[;"); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		if name == "" {
			continue
		}
		purl := "pkg:pypi/" + name
		if ver != "" {
			purl += "@" + ver
		}
		comps = append(comps, Component{Type: "library", Name: name, Version: ver, PURL: purl, BOMRef: "pypi:" + name + "@" + ver})
	}
	return comps
}

func parseDockerfile(path string) []Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var comps []Component
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if len(l) < 5 || !strings.EqualFold(l[:5], "FROM ") {
			continue
		}
		f := strings.Fields(strings.TrimSpace(l[5:]))
		if len(f) == 0 {
			continue
		}
		ref := f[0]
		if strings.EqualFold(ref, "scratch") || strings.HasPrefix(ref, "$") {
			continue
		}
		name, ver := ref, ""
		if i := strings.Index(ref, "@"); i >= 0 {
			name, ver = ref[:i], ref[i+1:]
		} else if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
			name, ver = ref[:i], ref[i+1:]
		}
		purl := "pkg:docker/" + name
		if ver != "" {
			purl += "@" + ver
		}
		comps = append(comps, Component{Type: "container", Name: name, Version: ver, PURL: purl, BOMRef: "docker:" + ref})
	}
	return comps
}

func dedup(in []Component) []Component {
	seen := map[string]bool{}
	var out []Component
	for _, c := range in {
		key := c.PURL
		if key == "" {
			key = c.Type + "|" + c.Name + "@" + c.Version
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// detUUID derives a stable RFC-4122-shaped UUID from a seed (no randomness, so
// SBOM output is reproducible for identical content).
func detUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
