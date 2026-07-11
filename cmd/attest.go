package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/optimal-cyber/caisson/internal/signing"
	"github.com/spf13/cobra"
)

var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Export and verify the vault's DSSE attestations (cosign-compatible)",
	Long: `Work with the vault's signed attestations.

Caisson signs its provenance, SBOM, and vulnerability attestations as standard
DSSE envelopes over in-toto v1 statements (Ed25519) — the same shape cosign
produces. 'attest export' lifts them out of the vault alongside the public key so
cosign (or any DSSE/in-toto verifier) can check them; 'attest verify' checks a
standalone envelope with just a public key, no cosign required.

Keyless signing (Sigstore Fulcio/Rekor, transparency logs) is intentionally out
of scope: it needs an online identity provider and log, which the airgap forbids.
Caisson stays key-based so signing and verification both work fully disconnected.`,
}

var attestExportOut string

var attestExportCmd = &cobra.Command{
	Use:   "export [package]",
	Short: "Export the vault's DSSE attestations + public key (cosign-verifiable)",
	Args:  cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		path := args[0]
		m, err := pkgformat.Open(path)
		if err != nil {
			return err
		}
		atts, err := pkgformat.ReadAttestations(path)
		if err != nil {
			return err
		}
		if len(atts) == 0 {
			return fmt.Errorf("attest export: %s carries no attestations (seal it with --key)", path)
		}

		dir := filepath.Join(attestExportOut, m.Name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}

		note(c, "attest export: %s\n", path)
		var written []string
		for _, a := range atts {
			p := filepath.Join(dir, a.OutFile)
			if err := os.WriteFile(p, a.Envelope, 0o644); err != nil {
				return err
			}
			written = append(written, p)
			note(c, "  ✓ %-11s → %s", a.Kind, p)
		}

		pub, ok, err := pkgformat.SignerPublicKeyPEM(path)
		if err != nil {
			return err
		}
		if ok {
			p := filepath.Join(dir, "cosign.pub")
			if err := os.WriteFile(p, pub, 0o644); err != nil {
				return err
			}
			written = append(written, p)
			note(c, "  ✓ public key  → %s", p)
		}

		note(c, "\n  wrote %d files. These are standard DSSE / in-toto v1 envelopes.", len(written))
		note(c, "\n  verify offline (no cosign needed):")
		note(c, "    caisson attest verify %s --key %s", filepath.Join(dir, atts[0].OutFile), filepath.Join(dir, "cosign.pub"))
		note(c, "\n  verify with cosign (key-based, offline):")
		note(c, "    cosign verify-blob-attestation --key %s \\", filepath.Join(dir, "cosign.pub"))
		note(c, "        --insecure-ignore-tlog --check-claims=false \\")
		note(c, "        --signature %s <artifact>", filepath.Join(dir, atts[0].OutFile))
		note(c, "\n  (keyless Fulcio/Rekor is out of scope — it needs an online log)")
		return nil
	},
}

var attestVerifyKey string

var attestVerifyCmd = &cobra.Command{
	Use:   "verify [envelope.dsse.json]",
	Short: "Verify a standalone DSSE attestation envelope with a public key (offline)",
	Args:  cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		if attestVerifyKey == "" {
			return fmt.Errorf("attest verify: --key <public.pem> is required")
		}
		envBytes, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var env signing.Envelope
		if err := json.Unmarshal(envBytes, &env); err != nil {
			return fmt.Errorf("attest verify: %s is not a DSSE envelope: %w", args[0], err)
		}
		pubPEM, err := os.ReadFile(attestVerifyKey)
		if err != nil {
			return err
		}
		key, err := signing.LoadPublic(pubPEM)
		if err != nil {
			return err
		}

		payload, ok := key.VerifyDSSE(&env)

		var stmt struct {
			Type          string `json:"_type"`
			PredicateType string `json:"predicateType"`
			Subject       []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
		}
		_ = json.Unmarshal(payload, &stmt)

		note(c, "attest verify: %s\n", args[0])
		note(c, "  payloadType   %s", env.PayloadType)
		if stmt.Type != "" {
			note(c, "  statement     %s", stmt.Type)
		}
		if stmt.PredicateType != "" {
			note(c, "  predicate     %s", stmt.PredicateType)
		}
		for _, s := range stmt.Subject {
			note(c, "  subject       %s (sha256:%s)", s.Name, short(s.Digest["sha256"]))
		}
		if !ok {
			note(c, "\n  ✗ signature does NOT verify against the provided key")
			return fmt.Errorf("attest verify: signature verification failed for %s", args[0])
		}
		note(c, "\n  ✓ signature verified against the provided key (keyId %s)", short(key.KeyID()))
		return nil
	},
}

func init() {
	attestExportCmd.Flags().StringVar(&attestExportOut, "out", "./attestations", "directory to write the DSSE envelopes + public key into")
	attestVerifyCmd.Flags().StringVar(&attestVerifyKey, "key", "", "public key (PEM) to verify the envelope against")
	attestCmd.AddCommand(attestExportCmd, attestVerifyCmd)
	rootCmd.AddCommand(attestCmd)
}
