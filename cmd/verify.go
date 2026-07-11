package cmd

import (
	"fmt"
	"os"

	"github.com/optimal-cyber/caisson/internal/pkgformat"
	"github.com/spf13/cobra"
)

var verifyKey string

var verifyCmd = &cobra.Command{
	Use:   "verify [package]",
	Short: "Verify a vault's seal, signature, and provenance",
	Long: `Verify a sealed vault.

Checks three things: the payload digest matches the sealed manifest, the vault's
Ed25519 signature over the manifest is valid, and the DSSE-wrapped SLSA
provenance attestation is valid. Pass --key <public.pem> to also confirm the
vault was signed by a specific trusted key. Exits non-zero on any failure.`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

// packageVerifyCmd is the same command under the `package` group.
var packageVerifyCmd = &cobra.Command{
	Use:   "verify [package]",
	Short: "Verify a vault's seal, signature, and provenance",
	Long:  verifyCmd.Long,
	Args:  cobra.ExactArgs(1),
	RunE:  runVerify,
}

func runVerify(c *cobra.Command, args []string) error {
	path := args[0]

	sealOK, m, err := pkgformat.Verify(path)
	if err != nil {
		return err
	}
	note(c, "verify: %s\n", path)
	if sealOK {
		note(c, "  ✓ seal        payload digest matches manifest")
	} else {
		note(c, "  ✗ seal        payload digest does NOT match manifest")
	}
	note(c, "                %s", m.Digest)

	var providedPub []byte
	if verifyKey != "" {
		providedPub, err = os.ReadFile(verifyKey)
		if err != nil {
			return err
		}
	}
	sr, err := pkgformat.VerifySignature(path, providedPub)
	if err != nil {
		return err
	}

	switch {
	case !sr.Present:
		note(c, "  · signature   none (vault is unsigned)")
	case sr.Valid:
		note(c, "  ✓ signature   valid Ed25519 signature (keyId %s)", short(sr.KeyID))
	default:
		note(c, "  ✗ signature   INVALID")
	}
	if sr.Present {
		switch {
		case sr.IdentityMatch == nil:
			note(c, "  · identity    verified against the vault's embedded key only (pass --key to pin a trusted signer)")
		case *sr.IdentityMatch:
			note(c, "  ✓ identity    signed by the provided public key")
		default:
			note(c, "  ✗ identity    NOT signed by the provided public key")
		}
		if sr.ProvenancePresent {
			if sr.ProvenanceValid {
				note(c, "  ✓ provenance  SLSA attestation signature valid")
			} else {
				note(c, "  ✗ provenance  SLSA attestation signature INVALID")
			}
		}
		if sr.SBOMAttestationPresent {
			if sr.SBOMAttestationValid {
				note(c, "  ✓ sbom        CycloneDX attestation signature valid")
			} else {
				note(c, "  ✗ sbom        CycloneDX attestation signature INVALID")
			}
		}
		if sr.VulnAttestationPresent {
			if sr.VulnAttestationValid {
				note(c, "  ✓ vuln        scan attestation signature valid")
			} else {
				note(c, "  ✗ vuln        scan attestation signature INVALID")
			}
		}
	}

	failed := !sealOK ||
		(sr.Present && !sr.Valid) ||
		(sr.IdentityMatch != nil && !*sr.IdentityMatch) ||
		(sr.ProvenancePresent && !sr.ProvenanceValid) ||
		(sr.SBOMAttestationPresent && !sr.SBOMAttestationValid) ||
		(sr.VulnAttestationPresent && !sr.VulnAttestationValid)
	if failed {
		return fmt.Errorf("verify: verification failed for %s", path)
	}
	note(c, "\n  ✓ verified")
	return nil
}

func init() {
	verifyCmd.Flags().StringVar(&verifyKey, "key", "", "public key (PEM) to pin the expected signer")
	packageVerifyCmd.Flags().StringVar(&verifyKey, "key", "", "public key (PEM) to pin the expected signer")
	rootCmd.AddCommand(verifyCmd)
	packageCmd.AddCommand(packageVerifyCmd)
}
