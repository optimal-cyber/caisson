# Deploying with Caisson

Three steps: **seal** a release on the connected side, **carry** it across the airgap, then
**verify + deploy** on the disconnected side. The SBOM, scan, and control evidence travel
sealed inside the one `.caisson` file — nothing to reconstruct on the far end.

> Sample output below is real (captured from the CLI), lightly trimmed.

## Install

```bash
git clone https://github.com/optimal-cyber/caisson && cd caisson
go build -o caisson .          # Go 1.22+
# or:  go install github.com/optimal-cyber/caisson@latest
```

Use `./caisson` from the repo, or put the binary on your `PATH`.

---

## 1 · Seal the release  (connected side)

```bash
caisson key gen --out caisson                       # one-time: Ed25519 keypair
caisson package create ./examples/hello-app \
    --key caisson.key \
    --scan-report scan.grype.json                   # a Grype/Trivy JSON you produced
```

```text
package create: sealed "./examples/hello-app"

  ✓ read examples/hello-app/caisson.yaml
  ✓ packed 7 files · 2.4 KB
  ✓ per-file SHA-256 recorded · content digest computed
  ✓ CycloneDX 1.6 SBOM embedded (4 components)
  ✓ grype scan embedded (3 findings: 1 high, 1 medium, 1 low)
  ✓ frameworks mapped: NIST SP 800-53 Rev 5, CMMC 2.0 Level 2
  ✓ manifest sealed (format 0.1.0)
  ✓ signed (ed25519, keyId c73176615a07…) · SLSA provenance + CycloneDX SBOM attested

  vault → hello-app.caisson   (hello-app v1.0.0)
  digest  sha256:e7119eb699a8e92276c4fb491704db0ade56ee70f094f17f43d23c87bce69232
```

`package create` reads a `caisson.yaml` when present (name, version, source, images, k8s
manifests, frameworks, signing key); flags override it. Add `--pull-images` to pull the
referenced container images into an OCI layout sealed inside the vault (needs registry access).

---

## 2 · Carry it across the gap

Move the single `hello-app.caisson` file across your one-way transfer / data diode /
sneakernet. It's a standard gzip+tar — inspect it anywhere with `tar -tzf hello-app.caisson`.
It carries the payload, manifest, SBOM, scan, and the signed attestations.

---

## 3 · Verify + deploy  (disconnected side)

```bash
caisson verify hello-app.caisson --key caisson.pub
```

```text
verify: hello-app.caisson

  ✓ seal        payload digest matches manifest
  ✓ signature   valid Ed25519 signature (keyId c73176615a07…)
  ✓ identity    signed by the provided public key
  ✓ provenance  SLSA attestation signature valid
  ✓ sbom        CycloneDX attestation signature valid
  ✓ vuln        scan attestation signature valid

  ✓ verified
```

```bash
caisson deploy hello-app.caisson --require-signature --deny-severity critical
```

```text
deploy: hello-app.caisson → enclave-prod / default

  ✓ seal verified · payload digest matches manifest
  ✓ signature verified (keyId c73176615a07…) · SLSA provenance valid, SBOM attestation valid, vuln attestation valid
  · vulnerability scan (grype): 3 findings [1 high, 1 medium, 1 low]
  ✓ policy gate passed
  · found 2 kubernetes manifest(s) in payload
      - k8s/deployment.yaml
      - k8s/service.yaml

  dry run — pass --apply to execute (needs a reachable registry + cluster):
  · would apply 2 workload(s) to enclave-prod/default via kubectl
```

Seal, signature, and the policy gate always run **first**. Without `--apply`, deploy prints the
plan (a safe dry run).

### It refuses a non-compliant vault (non-zero exit)

```bash
caisson deploy hello-app.caisson --require-signature --deny-severity high
```

```text
  ✗ POLICY GATE FAILED — refusing to deploy:
      - 1 finding(s) at or above "high" (--deny-severity)
caisson: deploy: policy gate failed for hello-app.caisson      # exit code 1
```

A tampered, unsigned/mis-signed, or policy-violating vault is rejected before anything is
delivered — so a bad artifact can't land in the enclave, and CI can gate on the exit code.

### Real delivery — `--apply`

```bash
caisson deploy hello-app.caisson --require-signature --apply \
    --registry registry.enclave.local:5000 \
    --namespace prod --evidence-export
```

With `--apply`, Caisson pushes the sealed images to your registry (via go-containerregistry) and
applies the workloads with `kubectl` — or, when the `caisson.yaml` declares a `helm:` chart
carried in the payload, installs it with `helm upgrade --install` — wrapping the tools you already
run. This needs a **reachable registry and Kubernetes cluster with credentials**;
`--evidence-export` also writes the assessment-ready evidence bundle on arrival.

---

## The policy gate (flags)

| Flag | Effect |
|------|--------|
| `--require-signature` | Refuse unless the vault is validly signed |
| `--deny-severity critical\|high\|medium\|low` | Refuse if the scan has findings at/above this severity (fail-closed if no scan is attached) |
| `--apply` | Execute the delivery (registry push + `kubectl apply`); omit for a dry-run plan |
| `--evidence-export` | Write the OSCAL-aligned evidence bundle on arrival |

Full command reference: `caisson --help` (and `caisson <command> --help`).
