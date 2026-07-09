<p align="center">
  <img src="brand/caisson-vault-logomark.svg" width="128" height="128" alt="Caisson vault emblem"/>
</p>

<h1 align="center">Caisson</h1>

<p align="center"><em>Compliance-native airgap delivery.</em></p>

<p align="center">
  <strong>Nothing crosses the gap unsealed.</strong><br/>
  Sealed at the source. Evidence on arrival.
</p>

<p align="center">
  <code>caisson package create ./my-app</code> &nbsp;→&nbsp; <code>caisson deploy my-app.caisson --evidence-export</code>
</p>

---

> **Status: scaffold.** Every command runs and prints realistic placeholder output.
> The package format, compliance evidence, and deploy logic live behind stable
> interfaces (`internal/pkgformat`, `internal/evidence`, `internal/deploy`) ready
> for real implementation.

## Vision

Getting software into an airgapped environment is a solved-ish problem. Getting it in
*with proof* is not.

Today, teams shipping into disconnected DoD and critical-infrastructure enclaves move the
artifact one way and the compliance story another: the SBOM lives in a pipeline log, the
NIST 800-53 / CMMC control mappings live in a binder, the provenance lives in someone's
memory — and all three drift apart the moment the artifact leaves the connected side. Six
months later an assessor asks "what's actually running behind the gap, and prove it," and
the answer is a scramble.

**Caisson makes the package carry its own evidence.** A Caisson vault seals an application
together with its signed SBOM, its mapped control evidence, and its cryptographic
provenance into a single portable artifact. What lands in the disconnected environment
arrives sealed, signed, and **assessment-ready** — the evidence is a first-class part of
the payload, not a parallel paper trail.

Target users: **DoD programs, defense contractors, and regulated critical infrastructure.**

### What Caisson is *not*

Caisson is **complementary to existing airgap tooling, not a replacement for it.** It does
not reinvent airgap transfer, OCI registries, or Kubernetes — it wraps the registries and
clusters you already run and adds the compliance layer on top. If you already move bits
across the gap with tooling you trust, Caisson rides alongside it and makes the evidence
travel sealed with the payload.

## Quickstart

```bash
# build the scaffold
go build -o caisson .

# 0. scaffold a project (writes caisson.yaml)
./caisson init

# 1. SEAL a release at the source — SBOM + control evidence computed once
./caisson package create ./my-app
#   ✓ resolved 4 components · SBOM sealed
#   ✓ mapped NIST 800-53 + CMMC control evidence · attached
#   ✓ provenance signed · vault ready → my-app.caisson

# 2. INSPECT what a sealed vault carries (read-only, nothing deployed)
./caisson package inspect my-app.caisson

# 3. read the sealed SBOM
./caisson sbom view my-app.caisson

# 4. export the assessment-ready evidence bundle
./caisson evidence export my-app.caisson --out ./evidence

# 5. DEPLOY across the gap and export evidence on arrival
./caisson deploy my-app.caisson --evidence-export
#   ✓ seal verified · provenance intact
#   ✓ images pushed to airgapped registry · workloads applied
#   ✓ evidence bundle exported → ./evidence/

# run caisson with no arguments for the map (and one honest promise)
./caisson
```

> `caisson deploy` is the convenience form of `caisson package deploy` — both do the same thing.

## Architecture

Caisson has two halves: **seal on the connected side, verify-and-apply on the disconnected
side.** In between, the vault crosses the airgap however you already move bits (data diode,
sneakernet, one-way transfer). The compliance evidence rides *inside* the vault the whole way.

```mermaid
flowchart LR
  subgraph CONNECTED["🌐 Connected side (build)"]
    SRC["source · images · workloads"]
    CREATE["caisson package create"]
    VAULT["📦 my-app.caisson<br/>payload + SBOM<br/>+ control evidence<br/>+ signed provenance"]
    SRC --> CREATE --> VAULT
  end

  VAULT -->|"⇢ across the airgap<br/>(diode / sneakernet)"| VERIFY

  subgraph DISCONNECTED["🔒 Disconnected enclave"]
    VERIFY["caisson deploy<br/>(verify seal + provenance)"]
    REG[("OCI registry")]
    K8S["Kubernetes"]
    EV["📑 evidence bundle<br/>OSCAL + human-readable"]
    VERIFY -->|push images| REG
    VERIFY -->|apply workloads| K8S
    VERIFY -->|--evidence-export| EV
    REG --> K8S
    EV --> ASSESS["ISSM · assessors · SCA"]
  end
```

If Mermaid doesn't render, the flow is: **source → `package create` → sealed `.caisson`
vault (payload + SBOM + evidence + provenance) → across the airgap → `deploy` verifies the
seal → pushes images to your OCI registry, applies workloads to Kubernetes, and exports the
evidence bundle for assessors.**

### How it interoperates (rather than reinventing)

| Layer | Caisson provides | Caisson reuses (does not reinvent) |
|---|---|---|
| Transfer across the gap | a self-describing sealed artifact to move | your existing one-way transfer / diode / sneakernet |
| Image distribution | seal verification + push orchestration | **OCI registries** on the disconnected side |
| Workload delivery | manifest capture + apply on arrival | **Kubernetes** in the enclave |
| Supply chain | signed SBOM sealed into the vault | SPDX / CycloneDX, cosign, SLSA provenance |
| Compliance | control mappings + assessment bundle export | NIST 800-53, CMMC, OSCAL |

The internal packages mirror this split, so real implementation drops into stable seams:

```
caisson/
├── main.go                     # entrypoint
├── cmd/                        # cobra commands (thin; render only)
│   ├── root.go  init.go  package.go  deploy.go  sbom.go  evidence.go
└── internal/
    ├── pkgformat/              # the .caisson vault format: pack, inspect, seal, SBOM
    ├── evidence/               # NIST 800-53 / CMMC control mapping + bundle export
    ├── deploy/                 # verify seal → OCI registry push → k8s apply → evidence
    └── brand/                  # shared identity strings + terminal banner
```

## Meet Caisson

<img src="brand/caisson-helm-logomark.svg" width="96" height="96" align="right" alt="Caisson's helm"/>

Caisson is our mascot — an armored combat-engineer guardian who carries a sealed hexagonal
vault on his back across denied territory. He learned two trades nobody else would take:
sinking foundations under crushing pressure where ordinary builders buckle, and hauling
live payloads across ground where the road home is already cut. He never asks what's inside
the vault. He only guarantees it lands **sealed, signed, and standing**.

> **"Nothing crosses the gap unsealed."**

The full character sheet, palette, and art live in [`brand/`](brand/).

---

<p align="center">
  A <a href="https://gooptimal.io">GoOptimal</a> project by Optimal&nbsp;Labs.<br/>
  <sub>Caisson is complementary to existing airgap tooling — not a replacement for it.</sub>
</p>
