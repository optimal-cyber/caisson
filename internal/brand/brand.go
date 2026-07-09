// Package brand holds shared identity strings and the terminal banner so the
// CLI stays consistent with brand/CHARACTER-SHEET.md. If a name or tagline
// appears in the binary, it comes from here.
package brand

// Identity constants. Keep these in sync with brand/CHARACTER-SHEET.md.
const (
	Name        = "Caisson"
	Version     = "0.0.0-scaffold"
	Tagline     = "Compliance-native airgap delivery."
	Catchphrase = "Nothing crosses the gap unsealed."
	// CLITag is printed when caisson runs with no arguments.
	CLITag = "If it isn't sealed, it isn't shipped."
)

// Banner returns the ASCII vault shown on `caisson` with no arguments.
func Banner() string { return banner }

const banner = `
       .------------.
      /  o   o   o   \      C A I S S O N
     |  [ == SEAL == ] |    ` + Tagline + `
      \  o   o   o   /      "` + Catchphrase + `"
       '------------'
`
