package pkgformat

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
