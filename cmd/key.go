package cmd

import (
	"os"

	"github.com/optimal-cyber/caisson/internal/signing"
	"github.com/spf13/cobra"
)

var keyOut string

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage Caisson signing keys",
	Long:  "Generate and manage the Ed25519 keys used to sign vaults and attestations.",
}

var keyGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate an Ed25519 signing keypair",
	Long: `Generate an Ed25519 keypair for signing vaults.

Writes <out>.key (private, mode 0600) and <out>.pub (public). The private key is
not passphrase-encrypted yet; keep it secret. Sigstore/cosign keyless signing is
a documented follow-on.`,
	Args: cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		k, err := signing.Generate()
		if err != nil {
			return err
		}
		priv, err := k.PrivatePEM()
		if err != nil {
			return err
		}
		pub, err := k.PublicPEM()
		if err != nil {
			return err
		}
		privPath := keyOut + ".key"
		pubPath := keyOut + ".pub"
		if err := os.WriteFile(privPath, priv, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
			return err
		}
		note(c, "key gen: generated Ed25519 keypair (keyId %s)\n", short(k.KeyID()))
		note(c, "  private → %s  (keep secret · mode 0600)", privPath)
		note(c, "  public  → %s", pubPath)
		note(c, "\n  sign a vault:  caisson package create ./src --key %s", privPath)
		note(c, "  verify:        caisson verify <vault>.caisson --key %s", pubPath)
		return nil
	},
}

func init() {
	keyGenCmd.Flags().StringVar(&keyOut, "out", "caisson", "output basename (writes <out>.key and <out>.pub)")
	keyCmd.AddCommand(keyGenCmd)
	rootCmd.AddCommand(keyCmd)
}
