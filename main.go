// Command caisson is the CLI for compliance-native airgap delivery.
//
// Caisson seals an application together with its SBOM attestations,
// NIST 800-53 / CMMC control evidence, and cryptographic provenance into a
// single portable vault, carries it across the airgap, and verifies the seal
// on arrival — so what lands in the disconnected environment is signed and
// assessment-ready.
//
// This binary is currently a scaffold: every command prints realistic
// placeholder output describing what it will do. The real logic lives behind
// stable interfaces in internal/pkgformat, internal/evidence, and
// internal/deploy, ready to be filled in.
package main

import "github.com/optimal-cyber/caisson/cmd"

func main() {
	cmd.Execute()
}
