package pkgformat

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractedAttestation is one DSSE attestation lifted out of a vault, ready to
// hand to cosign or any other DSSE/in-toto verifier.
type ExtractedAttestation struct {
	Kind     string // "provenance" | "sbom" | "vuln"
	OutFile  string // suggested standalone filename
	Envelope []byte // the DSSE envelope JSON, exactly as sealed
}

// ReadAttestations returns the DSSE attestation envelopes present in the vault.
// The envelopes are standard DSSE over in-toto v1 statements (Ed25519), so they
// verify with cosign, in-toto, or `caisson attest verify` given the public key.
func ReadAttestations(path string) ([]ExtractedAttestation, error) {
	specs := []struct{ kind, member, out string }{
		{"provenance", provenanceName, "provenance.dsse.json"},
		{"sbom", sbomAttName, "sbom.dsse.json"},
		{"vuln", scanAttName, "vuln.dsse.json"},
	}
	var out []ExtractedAttestation
	for _, s := range specs {
		data, ok, err := readMember(path, s.member)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, ExtractedAttestation{Kind: s.kind, OutFile: s.out, Envelope: data})
	}
	return out, nil
}

// SignerPublicKeyPEM returns the signer's public key (PKIX PEM) recorded in the
// vault's signature, suitable for `cosign verify-blob-attestation --key`. The
// bool is false for an unsigned vault.
func SignerPublicKeyPEM(path string) ([]byte, bool, error) {
	data, ok, err := readMember(path, signatureName)
	if err != nil || !ok {
		return nil, false, err
	}
	var sig Signature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, false, fmt.Errorf("pkgformat: decoding signature: %w", err)
	}
	pemBytes, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return nil, false, err
	}
	return pemBytes, true, nil
}

// ExtractPayloadTree extracts every payload file at or under prefix (a directory
// path relative to the sealed source) into destDir, preserving structure. It
// returns the number of files written — 0 means the subtree isn't in the vault.
// Used by deploy to hand a sealed Helm chart to `helm`.
func ExtractPayloadTree(vaultPath, destDir, prefix string) (int, error) {
	prefix = strings.Trim(filepath.ToSlash(prefix), "/")

	f, err := os.Open(vaultPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer gz.Close()

	n := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		if !strings.HasPrefix(hdr.Name, payloadPrefix) || hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel := strings.TrimPrefix(hdr.Name, payloadPrefix)
		if rel != prefix && !strings.HasPrefix(rel, prefix+"/") {
			continue
		}
		out := filepath.Join(destDir, filepath.FromSlash(rel))
		if !strings.HasPrefix(out, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return n, fmt.Errorf("pkgformat: unsafe payload path %q", hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return n, err
		}
		w, err := os.Create(out)
		if err != nil {
			return n, err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return n, err
		}
		if err := w.Close(); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
