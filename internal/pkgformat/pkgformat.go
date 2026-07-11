// Package pkgformat implements the ".caisson" vault: a gzip-compressed tar
// archive that carries an application payload alongside a manifest recording a
// per-file SHA-256 inventory and an overall content digest. Every vault also
// embeds a CycloneDX SBOM (bound to the signed manifest by digest); optionally
// the vault is signed (Ed25519) and carries DSSE-wrapped SLSA provenance and
// CycloneDX SBOM attestations.
//
// Create packs a directory into a vault on disk (signing it when a key is
// given), Open reads the manifest back, Verify recomputes the payload digest and
// checks SBOM integrity, and VerifySignature checks the signature and
// attestations. Standard-library only, so it works in a disconnected
// environment.
package pkgformat

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/optimal-cyber/caisson/internal/attest"
	"github.com/optimal-cyber/caisson/internal/oci"
	"github.com/optimal-cyber/caisson/internal/sbom"
	"github.com/optimal-cyber/caisson/internal/signing"
	"github.com/optimal-cyber/caisson/internal/vuln"
)

const (
	// Extension is the file suffix for a sealed Caisson vault.
	Extension = ".caisson"
	// FormatVersion is the vault layout version written into the manifest.
	FormatVersion = "0.1.0"

	manifestName   = "manifest.json"
	signatureName  = "signature.json"
	sbomFileName   = "sbom.cdx.json"
	scanFileName   = "scan.json"
	provenanceName = "attestations/provenance.dsse.json"
	sbomAttName    = "attestations/sbom.dsse.json"
	scanAttName    = "attestations/vuln.dsse.json"
	payloadPrefix  = "payload/"
	imagesPrefix   = "images/"
)

// FileEntry is one payload file recorded in the manifest inventory.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	Type   string `json:"type"`
	SHA256 string `json:"sha256"`
}

// SBOMRef records the SBOM embedded in the vault, bound to the signed manifest.
type SBOMRef struct {
	Format      string `json:"format"`
	SpecVersion string `json:"specVersion"`
	Generator   string `json:"generator,omitempty"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Components  int    `json:"components"`
}

// ScanRef records the vulnerability scan embedded in the vault, bound to the
// signed manifest.
type ScanRef struct {
	Source string         `json:"source"`
	Path   string         `json:"path"`
	SHA256 string         `json:"sha256"`
	Total  int            `json:"total"`
	Counts map[string]int `json:"counts"`
}

// ImageRef records a container image the workload references. At create time a
// vault records the declared reference (Pulled=false); pulling the image into
// an OCI layout inside the vault fills in Digest and Path (needs registry
// access).
type ImageRef struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest,omitempty"`
	Path      string `json:"path,omitempty"`
	Pulled    bool   `json:"pulled"`
}

// Manifest is the sealed metadata carried inside every vault (manifest.json).
type Manifest struct {
	FormatVersion string      `json:"formatVersion"`
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	Created       string      `json:"created"`
	Source        string      `json:"source"`
	FileCount     int         `json:"fileCount"`
	TotalSize     int64       `json:"totalSize"`
	Digest        string      `json:"digest"`
	Signed        bool        `json:"signed"`
	Frameworks    []string    `json:"frameworks,omitempty"`
	Images        []ImageRef  `json:"images,omitempty"`
	Workloads     []string    `json:"workloads,omitempty"`
	Chart         string      `json:"chart,omitempty"`   // Helm chart path (relative to source) to apply
	Release       string      `json:"release,omitempty"` // Helm release name
	SBOM          *SBOMRef    `json:"sbom,omitempty"`
	Scan          *ScanRef    `json:"scan,omitempty"`
	Files         []FileEntry `json:"files"`
}

// Filename returns the canonical vault filename for this manifest.
func (m *Manifest) Filename() string { return m.Name + Extension }

// Signature is the detached signature record stored in the vault (signature.json).
type Signature struct {
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"keyId"`
	PublicKey      string `json:"publicKey"` // base64 of the PKIX PEM
	ManifestSHA256 string `json:"manifestSha256"`
	Signature      string `json:"signature"` // base64 of Sign(manifest.json bytes)
}

// CreateOptions configures Create.
type CreateOptions struct {
	Name       string       // defaults to the source directory's base name
	Version    string       // defaults to "0.0.0"
	Now        time.Time    // defaults to time.Now().UTC(); injectable for tests
	Signer     *signing.Key // when set, the vault is signed and attestations are added
	Scan       *vuln.Report // when set, the scan is embedded and (if signing) attested
	Frameworks []string     // compliance frameworks the evidence is asserted to map to
	Images     []string     // container image references the workload declares
	Workloads  []string     // k8s manifest paths (relative to source) to apply on arrival
	Chart      string       // Helm chart path (relative to source) to apply on arrival
	Release    string       // Helm release name
	Syft       bool         // generate the SBOM with Anchore Syft (deep) instead of native detection

	// ImageLayoutDir, when set, is a directory holding an OCI image layout to
	// seal into the vault under images/. PulledDigests maps declared image
	// references to the content-addressed digest pulled into that layout; those
	// references are recorded in the manifest as pulled.
	ImageLayoutDir string
	PulledDigests  map[string]string
}

// Create packs source (a directory) into "<name>.caisson" in the current
// working directory. It returns the sealed manifest and the output path.
func Create(source string, opts CreateOptions) (*Manifest, string, error) {
	info, err := os.Stat(source)
	if err != nil {
		return nil, "", err
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("pkgformat: source %q is not a directory", source)
	}

	name := opts.Name
	if name == "" {
		name = filepath.Base(filepath.Clean(source))
	}
	version := opts.Version
	if version == "" {
		version = "0.0.0"
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	files, total, err := inventory(source)
	if err != nil {
		return nil, "", err
	}

	sbomResult, err := sbom.Collect(source, name, version, now, opts.Syft)
	if err != nil {
		return nil, "", err
	}
	sbomBytes := sbomResult.JSON
	sbomSum := sha256.Sum256(sbomBytes)

	var scanBytes []byte
	var scanRef *ScanRef
	if opts.Scan != nil {
		scanBytes, err = opts.Scan.JSON()
		if err != nil {
			return nil, "", err
		}
		scanSum := sha256.Sum256(scanBytes)
		scanRef = &ScanRef{
			Source: opts.Scan.Source,
			Path:   scanFileName,
			SHA256: hex.EncodeToString(scanSum[:]),
			Total:  len(opts.Scan.Findings),
			Counts: opts.Scan.Counts(),
		}
	}

	m := &Manifest{
		FormatVersion: FormatVersion,
		Name:          name,
		Version:       version,
		Created:       now.UTC().Format(time.RFC3339),
		Source:        filepath.ToSlash(source),
		FileCount:     len(files),
		TotalSize:     total,
		Digest:        digestOf(files),
		Signed:        opts.Signer != nil,
		Frameworks:    opts.Frameworks,
		Images:        buildImageRefs(opts.Images, opts.PulledDigests),
		Workloads:     opts.Workloads,
		Chart:         opts.Chart,
		Release:       opts.Release,
		SBOM: &SBOMRef{
			Format:      sbomResult.Format,
			SpecVersion: sbomResult.SpecVersion,
			Generator:   sbomResult.Generator,
			Path:        sbomFileName,
			SHA256:      hex.EncodeToString(sbomSum[:]),
			Components:  sbomResult.Components,
		},
		Scan:  scanRef,
		Files: files,
	}

	manifestJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, "", err
	}

	var sig *Signature
	var prov, sbomAtt, scanAtt *signing.Envelope
	if opts.Signer != nil {
		if sig, err = buildSignature(opts.Signer, manifestJSON); err != nil {
			return nil, "", err
		}
		if prov, err = buildProvenance(opts.Signer, m, now); err != nil {
			return nil, "", err
		}
		if sbomAtt, err = buildSBOMAttestation(opts.Signer, m, sbomBytes); err != nil {
			return nil, "", err
		}
		if opts.Scan != nil {
			if scanAtt, err = buildVulnAttestation(opts.Signer, m, opts.Scan); err != nil {
				return nil, "", err
			}
		}
	}

	out := name + Extension
	if err := writeArchive(out, source, opts.ImageLayoutDir, m, manifestJSON, sbomBytes, scanBytes, sig, prov, sbomAtt, scanAtt, now); err != nil {
		return nil, "", err
	}
	return m, out, nil
}

func buildSignature(k *signing.Key, manifestJSON []byte) (*Signature, error) {
	raw, err := k.Sign(manifestJSON)
	if err != nil {
		return nil, err
	}
	pubPEM, err := k.PublicPEM()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(manifestJSON)
	return &Signature{
		Algorithm:      "ed25519",
		KeyID:          k.KeyID(),
		PublicKey:      base64.StdEncoding.EncodeToString(pubPEM),
		ManifestSHA256: hex.EncodeToString(sum[:]),
		Signature:      base64.StdEncoding.EncodeToString(raw),
	}, nil
}

func buildProvenance(k *signing.Key, m *Manifest, now time.Time) (*signing.Envelope, error) {
	materials := make([]attest.ResourceDescriptor, 0, len(m.Files))
	for _, f := range m.Files {
		materials = append(materials, attest.ResourceDescriptor{
			Name:   f.Path,
			Digest: map[string]string{"sha256": f.SHA256},
		})
	}
	stmt := attest.Provenance(m.Name, m.Source, strings.TrimPrefix(m.Digest, "sha256:"), materials, now)
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	return k.WrapDSSE(payload)
}

func buildSBOMAttestation(k *signing.Key, m *Manifest, sbomBytes []byte) (*signing.Envelope, error) {
	// The predicate is the exact SBOM bytes embedded in the vault, so the
	// attestation and sbom.cdx.json are byte-identical.
	stmt := attest.SBOM(m.Name, strings.TrimPrefix(m.Digest, "sha256:"), json.RawMessage(sbomBytes))
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	return k.WrapDSSE(payload)
}

func buildVulnAttestation(k *signing.Key, m *Manifest, report *vuln.Report) (*signing.Envelope, error) {
	stmt := attest.Vuln(m.Name, strings.TrimPrefix(m.Digest, "sha256:"), report)
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	return k.WrapDSSE(payload)
}

// inventory walks dir, hashing every regular file, and returns the sorted
// FileEntry list plus the total byte size. It skips .git directories.
func inventory(dir string) ([]FileEntry, int64, error) {
	var files []FileEntry
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		total += size
		files = append(files, FileEntry{
			Path:   rel,
			Size:   size,
			Mode:   fmt.Sprintf("%04o", fi.Mode().Perm()),
			Type:   classify(rel),
			SHA256: sum,
		})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, total, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// buildImageRefs records the workload's declared image references. A reference
// present in pulled (ref -> content digest) was pulled into the vault's OCI
// layout, so it is recorded with its digest and layout path; the rest are
// declared-only (pulling them needs registry access).
func buildImageRefs(refs []string, pulled map[string]string) []ImageRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]ImageRef, 0, len(refs))
	for _, r := range refs {
		ref := ImageRef{Reference: r}
		if dg, ok := pulled[r]; ok {
			ref.Digest = dg
			ref.Path = imagesPrefix
			ref.Pulled = true
		}
		out = append(out, ref)
	}
	return out
}

// pulledDigests returns the content digests of images pulled into the vault's
// OCI layout, for integrity verification.
func pulledDigests(m *Manifest) []string {
	var out []string
	for _, img := range m.Images {
		if img.Pulled && img.Digest != "" {
			out = append(out, img.Digest)
		}
	}
	return out
}

// digestOf computes the overall content digest: sha256 over the sorted
// "sha256  path" lines. Independent of timestamps and archive framing.
func digestOf(files []FileEntry) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s  %s\n", f.SHA256, f.Path)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func writeArchive(outPath, source, imageLayoutDir string, m *Manifest, manifestJSON, sbomBytes, scanBytes []byte, sig *Signature, prov, sbomAtt, scanAtt *signing.Envelope, now time.Time) (err error) {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()

	gz := gzip.NewWriter(out)
	gz.Name = m.Name
	tw := tar.NewWriter(gz)

	if err := writeBytes(tw, manifestName, manifestJSON, now); err != nil {
		return err
	}
	if err := writeBytes(tw, sbomFileName, sbomBytes, now); err != nil {
		return err
	}
	if scanBytes != nil {
		if err := writeBytes(tw, scanFileName, scanBytes, now); err != nil {
			return err
		}
	}
	for _, part := range []struct {
		name string
		val  any
	}{
		{signatureName, sig},
		{provenanceName, prov},
		{sbomAttName, sbomAtt},
		{scanAttName, scanAtt},
	} {
		if isNil(part.val) {
			continue
		}
		data, err := json.MarshalIndent(part.val, "", "  ")
		if err != nil {
			return err
		}
		if err := writeBytes(tw, part.name, data, now); err != nil {
			return err
		}
	}
	for _, f := range m.Files {
		if err := copyFileEntry(tw, source, f, now); err != nil {
			return err
		}
	}
	if imageLayoutDir != "" {
		if err := writeLayoutFiles(tw, imageLayoutDir, now); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// writeLayoutFiles seals every file of an OCI image layout into the archive
// under images/, preserving the layout's directory structure.
func writeLayoutFiles(tw *tar.Writer, layoutDir string, now time.Time) error {
	return filepath.WalkDir(layoutDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(layoutDir, p)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:     imagesPrefix + filepath.ToSlash(rel),
			Mode:     0o644,
			Size:     info.Size(),
			ModTime:  now,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		return err
	})
}

func isNil(v any) bool {
	switch t := v.(type) {
	case *Signature:
		return t == nil
	case *signing.Envelope:
		return t == nil
	default:
		return v == nil
	}
}

func writeBytes(tw *tar.Writer, name string, data []byte, now time.Time) error {
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: now, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func copyFileEntry(tw *tar.Writer, source string, f FileEntry, now time.Time) error {
	abs := filepath.Join(source, filepath.FromSlash(f.Path))
	src, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer src.Close()

	hdr := &tar.Header{Name: payloadPrefix + f.Path, Mode: 0o644, Size: f.Size, ModTime: now, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, src)
	return err
}

// Open reads the manifest from a vault without extracting the payload.
func Open(path string) (*Manifest, error) {
	data, ok, err := readMember(path, manifestName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("pkgformat: %s not found in %s", manifestName, path)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("pkgformat: decoding manifest: %w", err)
	}
	return &m, nil
}

// ReadSBOM returns the embedded CycloneDX SBOM bytes, if present.
func ReadSBOM(path string) ([]byte, bool, error) {
	return readMember(path, sbomFileName)
}

// readMember returns the raw bytes of a named archive member.
func readMember(path, name string) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, false, fmt.Errorf("pkgformat: %s is not a valid vault: %w", path, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}
		if hdr.Name == name {
			data, err := io.ReadAll(tr)
			return data, true, err
		}
	}
	return nil, false, nil
}

// Verify recomputes the payload digest and checks the embedded SBOM's integrity
// against the manifest. A false result means the payload or SBOM was altered
// after sealing.
func Verify(path string) (ok bool, m *Manifest, err error) {
	m, err = Open(path)
	if err != nil {
		return false, nil, err
	}
	computed, err := payloadDigest(path)
	if err != nil {
		return false, m, err
	}
	ok = computed == m.Digest

	if m.SBOM != nil && !memberMatches(path, m.SBOM.Path, m.SBOM.SHA256) {
		ok = false
	}
	if m.Scan != nil && !memberMatches(path, m.Scan.Path, m.Scan.SHA256) {
		ok = false
	}
	if digests := pulledDigests(m); len(digests) > 0 {
		imagesOK, err := verifyImages(path, digests)
		if err != nil {
			return false, m, err
		}
		if !imagesOK {
			ok = false
		}
	}
	return ok, m, nil
}

// verifyImages extracts the sealed OCI layout to a temp directory and confirms
// each recorded image digest is present and re-hashes correctly. Because the
// digests ride inside the signed manifest and OCI blobs are content-addressed,
// a tampered image fails this check.
func verifyImages(vaultPath string, wantDigests []string) (bool, error) {
	tmp, err := os.MkdirTemp("", "caisson-verify-oci-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)

	found, err := extractLayout(vaultPath, tmp)
	if err != nil {
		return false, err
	}
	if !found {
		// The manifest records pulled images but no layout is sealed — tampered.
		return false, nil
	}
	if err := oci.VerifyLayout(tmp, wantDigests); err != nil {
		return false, nil
	}
	return true, nil
}

// ExtractImageLayout writes the vault's sealed OCI image layout into destDir
// (which becomes the layout root) and reports whether any layout was present.
// Used by deploy to push the sealed images to a registry on the far side.
func ExtractImageLayout(vaultPath, destDir string) (bool, error) {
	return extractLayout(vaultPath, destDir)
}

// ExtractPayloadFiles extracts the named payload files (paths relative to the
// sealed source) into destDir, returning their on-disk paths in the same order.
// It errors if any requested file is not present in the vault. Used by deploy to
// hand Kubernetes manifests to kubectl.
func ExtractPayloadFiles(vaultPath, destDir string, relPaths []string) ([]string, error) {
	want := make(map[string]bool, len(relPaths))
	for _, r := range relPaths {
		want[filepath.ToSlash(r)] = true
	}

	f, err := os.Open(vaultPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	found := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(hdr.Name, payloadPrefix) || hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel := strings.TrimPrefix(hdr.Name, payloadPrefix)
		if !want[rel] {
			continue
		}
		out := filepath.Join(destDir, filepath.FromSlash(rel))
		if !strings.HasPrefix(out, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return nil, fmt.Errorf("pkgformat: unsafe payload path %q", hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return nil, err
		}
		w, err := os.Create(out)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		found[rel] = out
	}

	paths := make([]string, 0, len(relPaths))
	for _, r := range relPaths {
		rel := filepath.ToSlash(r)
		p, ok := found[rel]
		if !ok {
			return nil, fmt.Errorf("pkgformat: %q not found in vault payload", r)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// extractLayout writes every images/ member of the vault into destDir (stripping
// the images/ prefix so destDir is the layout root). It reports whether any
// layout file was present.
func extractLayout(vaultPath, destDir string) (bool, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	defer gz.Close()

	found := false
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		if !strings.HasPrefix(hdr.Name, imagesPrefix) || hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel := strings.TrimPrefix(hdr.Name, imagesPrefix)
		out := filepath.Join(destDir, filepath.FromSlash(rel))
		// Guard against path traversal from a crafted archive.
		if !strings.HasPrefix(out, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return false, fmt.Errorf("pkgformat: unsafe layout path %q", hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return false, err
		}
		w, err := os.Create(out)
		if err != nil {
			return false, err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return false, err
		}
		if err := w.Close(); err != nil {
			return false, err
		}
		found = true
	}
	return found, nil
}

// memberMatches reports whether an archive member exists and its SHA-256 matches.
func memberMatches(path, name, wantSHA string) bool {
	data, present, err := readMember(path, name)
	if err != nil || !present {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == wantSHA
}

func payloadDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	var files []FileEntry
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(hdr.Name, payloadPrefix) || hdr.Typeflag != tar.TypeReg {
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, tr); err != nil {
			return "", err
		}
		files = append(files, FileEntry{
			Path:   strings.TrimPrefix(hdr.Name, payloadPrefix),
			SHA256: hex.EncodeToString(h.Sum(nil)),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return digestOf(files), nil
}

// SignatureResult reports the outcome of verifying a vault's signature.
type SignatureResult struct {
	Present                bool
	Valid                  bool // signature verifies against the vault's embedded key
	KeyID                  string
	IdentityMatch          *bool // set when a public key is provided: embedded key == provided?
	ProvenancePresent      bool
	ProvenanceValid        bool
	SBOMAttestationPresent bool
	SBOMAttestationValid   bool
	VulnAttestationPresent bool
	VulnAttestationValid   bool
}

// VerifySignature checks the vault's Ed25519 signature over the manifest and, if
// present, the DSSE-wrapped SLSA provenance and CycloneDX SBOM attestations.
// When providedPubPEM is non-nil it also reports whether the vault was signed by
// that specific key.
func VerifySignature(path string, providedPubPEM []byte) (*SignatureResult, error) {
	res := &SignatureResult{}

	sigBytes, ok, err := readMember(path, signatureName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return res, nil // unsigned vault
	}
	res.Present = true

	var sig Signature
	if err := json.Unmarshal(sigBytes, &sig); err != nil {
		return res, fmt.Errorf("pkgformat: decoding signature: %w", err)
	}
	res.KeyID = sig.KeyID

	pubPEM, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return res, err
	}
	key, err := signing.LoadPublic(pubPEM)
	if err != nil {
		return res, err
	}

	manifestJSON, ok, err := readMember(path, manifestName)
	if err != nil || !ok {
		return res, fmt.Errorf("pkgformat: manifest missing for signature check")
	}
	rawSig, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return res, err
	}
	res.Valid = key.Verify(manifestJSON, rawSig)

	if providedPubPEM != nil {
		provided, err := signing.LoadPublic(providedPubPEM)
		if err != nil {
			return res, err
		}
		match := provided.KeyID() == key.KeyID()
		res.IdentityMatch = &match
	}

	res.ProvenancePresent, res.ProvenanceValid = verifyEnvelope(path, provenanceName, key)
	res.SBOMAttestationPresent, res.SBOMAttestationValid = verifyEnvelope(path, sbomAttName, key)
	res.VulnAttestationPresent, res.VulnAttestationValid = verifyEnvelope(path, scanAttName, key)
	return res, nil
}

func verifyEnvelope(path, name string, key *signing.Key) (present, valid bool) {
	data, ok, err := readMember(path, name)
	if err != nil || !ok {
		return false, false
	}
	var env signing.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return true, false
	}
	_, v := key.VerifyDSSE(&env)
	return true, v
}

// classify maps a path to a coarse content type for the inventory.
func classify(path string) string {
	base := filepath.Base(path)
	if strings.EqualFold(base, "Dockerfile") || strings.HasSuffix(strings.ToLower(base), ".dockerfile") {
		return "dockerfile"
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return "k8s-manifest"
	case ".json":
		return "json"
	case ".go":
		return "go-source"
	case ".js", ".mjs", ".ts":
		return "javascript"
	case ".py":
		return "python"
	case ".sh":
		return "shell"
	case ".md":
		return "markdown"
	case ".txt":
		return "text"
	default:
		return "file"
	}
}
