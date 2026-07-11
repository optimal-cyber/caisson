package spec

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `name: hello-app
version: 1.2.3
source: app
images:
  - registry.airgap.local:5000/hello-app:1.2.3
  - registry.airgap.local:5000/sidecar:0.1.0
manifests:
  - k8s/deployment.yaml
  - k8s/service.yaml
frameworks:
  - NIST SP 800-53 Rev 5
  - CMMC 2.0 Level 2
signing:
  key: keys/caisson.key
`

func TestParseFields(t *testing.T) {
	s, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s.Name != "hello-app" || s.Version != "1.2.3" || s.Source != "app" {
		t.Errorf("scalar mismatch: %+v", s)
	}
	if len(s.Images) != 2 || s.Images[0] != "registry.airgap.local:5000/hello-app:1.2.3" {
		t.Errorf("images = %v", s.Images)
	}
	if len(s.Manifests) != 2 || s.Manifests[1] != "k8s/service.yaml" {
		t.Errorf("manifests = %v", s.Manifests)
	}
	if len(s.Frameworks) != 2 || s.Frameworks[0] != "NIST SP 800-53 Rev 5" {
		t.Errorf("frameworks = %v", s.Frameworks)
	}
	if s.Signing.Key != "keys/caisson.key" {
		t.Errorf("signing.key = %q", s.Signing.Key)
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	s, found, err := Load(dir)
	if err != nil || !found {
		t.Fatalf("Load found=%t err=%v", found, err)
	}
	if want := filepath.Join(dir, "app"); s.ResolvedSource() != want {
		t.Errorf("ResolvedSource = %q, want %q", s.ResolvedSource(), want)
	}
	if want := filepath.Join(dir, "keys/caisson.key"); s.ResolvedKey() != want {
		t.Errorf("ResolvedKey = %q, want %q", s.ResolvedKey(), want)
	}
}

func TestResolvedSourceDefaultsToDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("name: only-name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.ResolvedSource() != dir {
		t.Errorf("ResolvedSource = %q, want %q (source omitted → spec dir)", s.ResolvedSource(), dir)
	}
	if s.ResolvedKey() != "" {
		t.Errorf("ResolvedKey = %q, want empty when no key declared", s.ResolvedKey())
	}
}

func TestLoadMissingIsNotAnError(t *testing.T) {
	s, found, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load on empty dir: %v", err)
	}
	if found || s != nil {
		t.Errorf("expected not-found, got found=%t s=%v", found, s)
	}
}

func TestAbsolutePathsPassThrough(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(t.TempDir(), "elsewhere")
	body := "name: x\nsource: " + abs + "\n"
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.ResolvedSource() != abs {
		t.Errorf("absolute source rewritten: got %q want %q", s.ResolvedSource(), abs)
	}
}

func TestValidateRejectsEmpty(t *testing.T) {
	if _, err := Parse([]byte("version: 1.0.0\n")); err == nil {
		t.Error("expected error for a spec with neither name nor source")
	}
}

func TestParseTrimsAndDropsBlankEntries(t *testing.T) {
	s, err := Parse([]byte("name:  spaced  \nimages:\n  - ' a '\n  - ''\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "spaced" {
		t.Errorf("name not trimmed: %q", s.Name)
	}
	if len(s.Images) != 1 || s.Images[0] != "a" {
		t.Errorf("images not trimmed/compacted: %v", s.Images)
	}
}

func TestScaffoldRoundTrips(t *testing.T) {
	data := Scaffold(ScaffoldOptions{Name: "demo-app"})
	s, err := Parse(data)
	if err != nil {
		t.Fatalf("scaffold did not parse: %v\n%s", err, data)
	}
	if s.Name != "demo-app" {
		t.Errorf("name = %q, want demo-app", s.Name)
	}
	if s.Version != "0.1.0" {
		t.Errorf("default version = %q, want 0.1.0", s.Version)
	}
	if s.Source != "." {
		t.Errorf("default source = %q, want .", s.Source)
	}
	if len(s.Frameworks) == 0 {
		t.Error("scaffold omitted default frameworks")
	}
	if s.Signing.Key == "" {
		t.Error("scaffold omitted a signing key")
	}
	if len(s.Images) == 0 || len(s.Manifests) == 0 {
		t.Errorf("scaffold missing images/manifests: images=%v manifests=%v", s.Images, s.Manifests)
	}
}

func TestScaffoldHonorsOverrides(t *testing.T) {
	data := Scaffold(ScaffoldOptions{
		Name:       "svc",
		Version:    "2.0.0",
		Source:     "src",
		Frameworks: []string{"FedRAMP High"},
	})
	s, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != "2.0.0" || s.Source != "src" {
		t.Errorf("overrides not honored: %+v", s)
	}
	if len(s.Frameworks) != 1 || s.Frameworks[0] != "FedRAMP High" {
		t.Errorf("frameworks override not honored: %v", s.Frameworks)
	}
}
