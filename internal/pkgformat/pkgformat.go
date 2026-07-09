// Package pkgformat implements the ".caisson" vault: a gzip-compressed tar
// archive that carries an application payload alongside a manifest recording a
// per-file SHA-256 inventory and an overall content digest.
//
// This is the first real milestone. Create packs a directory into a vault on
// disk, Open reads the manifest back, and Verify recomputes the payload digest
// to detect tampering. Everything here is standard-library only, so it works in
// a disconnected environment. Signing (cosign), a full dependency SBOM (Syft),
// and the registry/Kubernetes deploy are layered on in later milestones.
package pkgformat

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
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
)

const (
	// Extension is the file suffix for a sealed Caisson vault.
	Extension = ".caisson"
	// FormatVersion is the vault layout version written into the manifest.
	FormatVersion = "0.1.0"

	manifestName  = "manifest.json"
	payloadPrefix = "payload/"
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

// CreateOptions configures Create.
type CreateOptions struct {
	Name    string    // defaults to the source directory's base name
	Version string    // defaults to "0.0.0"
	Now     time.Time // defaults to time.Now().UTC(); injectable for tests
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
		Signed:        false,
		Files:         files,
	}

	out := name + Extension
	if err := writeArchive(out, source, m, now); err != nil {
		return nil, "", err
	}
	return m, out, nil
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
// "sha256  path" lines. It is independent of timestamps and archive framing, so
// it is stable across rebuilds of identical content.
func digestOf(files []FileEntry) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s  %s\n", f.SHA256, f.Path)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func writeArchive(outPath, source string, m *Manifest, now time.Time) (err error) {
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

	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := writeBytes(tw, manifestName, mj, now); err != nil {
		return err
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
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		ModTime:  now,
		Typeflag: tar.TypeReg,
	}
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

	hdr := &tar.Header{
		Name:     payloadPrefix + f.Path,
		Mode:     0o644,
		Size:     f.Size,
		ModTime:  now,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, src)
	return err
}

// Open reads the manifest from a vault without extracting the payload.
func Open(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("pkgformat: %s is not a valid vault: %w", path, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == manifestName {
			var m Manifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				return nil, fmt.Errorf("pkgformat: decoding manifest: %w", err)
			}
			return &m, nil
		}
	}
	return nil, fmt.Errorf("pkgformat: %s not found in %s", manifestName, path)
}

// Verify recomputes the payload digest from the archive bytes and compares it to
// the sealed manifest digest. A false result means the payload was altered after
// sealing. (Manifest signing, which would also detect manifest tampering, is a
// later milestone.)
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
