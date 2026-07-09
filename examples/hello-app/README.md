# hello-app

A tiny sample application used to demonstrate `caisson package create`. It has
just enough shape — an app, a container build, and Kubernetes manifests — to make
the sealed vault's inventory and workload detection interesting.

```bash
caisson package create ./examples/hello-app --version 1.0.0
caisson package inspect hello-app.caisson
caisson sbom view hello-app.caisson
caisson deploy hello-app.caisson
```
