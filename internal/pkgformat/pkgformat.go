// Package pkgformat implements the ".caisson" vault: a gzip-compressed tar
// archive that carries an application payload alongside a manifest recording a
// per-file SHA-256 inventory and an overall content digest. Optionally the vault
// is signed (Ed25519) and carries a DSSE-wrapped SLSA provenance attestation.
//
// Create packs a directory into a vault on disk (signing it when a key is
// given), Open reads the manifest back, Verify recomputes the payload digest,
// and VerifySignature checks the signature and provenance. Standard-library only,
// so it works in a disconnected environment. A full dependency SBOM (Syft) and
// the registry/Kubernetes deploy are layered on in later milestones.
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
	"github.com/optimal-cyber/caisson/internal/signing"
)

const (
	// Extension is the file suffix for a sealed Caisson vault.
	Extension = ".caisson"
	// FormatVersion is the vault layout version written into the manifest.
	FormatVersion = "0.1.0"

	manifestName   = "manifest.json"
	signatureName  = "signature.json"
	provenanceName = "attestations/provenance.dsse.json"
	payloadPrefix  = "payload/"
)

// FileEntry is one payload file recorded in the manifest inventory.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	Type   string `json:"type"`
	SHA256 string `json:"sha256"`
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
	Name    string       // defaults to the source directory's base name
	Version string       // defaults to "0.0.0"
	Now     time.Time    // defaults to time.Now().UTC(); injectable for tests
	Signer  *signing.Key // when set, the vault is signed and provenance-attested
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
		Files:         files,
	}

	manifestJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, "", err
	}

	var sig *Signature
	var prov *signing.Envelope
	if opts.Signer != nil {
		if sig, err = buildSignature(opts.Signer, manifestJSON); err != nil {
			return nil, "", err
		}
		if prov, err = buildProvenance(opts.Signer, m, now); err != nil {
			return nil, "", err
		}
	}

	out := name + Extension
	if err := writeArchive(out, source, m, manifestJSON, sig, prov, now); err != nil {
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

// digestOf computes the overall content digest: sha256 over the sorted
// "sha256  path" lines. Independent of timestamps and archive framing, so it is
// stable across rebuilds of identical content.
func digestOf(files []FileEntry) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s  %s\n", f.SHA256, f.Path)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func writeArchive(outPath, source string, m *Manifest, manifestJSON []byte, sig *Signature, prov *signing.Envelope, now time.Time) (err error) {
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
	if sig != nil {
		sj, err := json.MarshalIndent(sig, "", "  ")
		if err != nil {
			return err
		}
		if err := writeBytes(tw, signatureName, sj, now); err != nil {
			return err
		}
	}
	if prov != nil {
		pj, err := json.MarshalIndent(prov, "", "  ")
		if err != nil {
			return err
		}
		if err := writeBytes(tw, provenanceName, pj, now); err != nil {
			return err
		}
	}
	for _, f := range m.Files {
		if err := copyFileEntry(tw, source, f, now); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
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

// Verify recomputes the payload digest from the archive bytes and compares it to
// the sealed manifest digest. A false result means the payload was altered after
// sealing.
func Verify(path string) (ok bool, m *Manifest, err error) {
	m, err = Open(path)
	if err != nil {
		return false, nil, err
	}
	computed, err := payloadDigest(path)
	if err != nil {
		return false, m, err
	}
	return computed == m.Digest, m, nil
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
	Present           bool
	Valid             bool // signature verifies against the vault's embedded key
	KeyID             string
	IdentityMatch     *bool // set when a public key is provided: embedded key == provided?
	ProvenancePresent bool
	ProvenanceValid   bool
}

// VerifySignature checks the vault's Ed25519 signature over the manifest and, if
// present, the DSSE-wrapped SLSA provenance. When providedPubPEM is non-nil it
// also reports whether the vault was signed by that specific key.
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

	provBytes, ok, err := readMember(path, provenanceName)
	if err != nil {
		return res, err
	}
	if ok {
		res.ProvenancePresent = true
		var env signing.Envelope
		if err := json.Unmarshal(provBytes, &env); err == nil {
			if _, valid := key.VerifyDSSE(&env); valid {
				res.ProvenanceValid = true
			}
		}
	}
	return res, nil
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
