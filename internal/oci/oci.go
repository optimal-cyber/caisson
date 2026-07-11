// Package oci pulls container images referenced by a package into an OCI image
// layout that travels sealed inside the vault, so the disconnected side has the
// images as well as the manifests that reference them.
//
// Writing and verifying the layout is content-addressed and needs no network:
// it is exercised offline in tests with in-memory images. Pull, by contrast, is
// the real fetch path — it reaches a registry and needs network access and
// credentials for the image being pulled. Caisson wraps go-containerregistry
// rather than reimplementing the registry protocol.
package oci

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

// LayoutDir is the vault-relative root the OCI image layout is stored under.
const LayoutDir = "images"

// refAnnotation records the original reference on a layout entry so a pulled
// image can be matched back to what the package declared.
const refAnnotation = "org.opencontainers.image.ref.name"

// pullTimeout bounds a Bundle's total registry interaction so an unreachable
// registry fails cleanly instead of hanging indefinitely.
const pullTimeout = 90 * time.Second

// Pulled records one image written into the layout.
type Pulled struct {
	Reference string // the reference as requested
	Digest    string // the content-addressed image digest (sha256:...)
}

// Pull fetches an image from a registry. This is the real fetch path: it needs
// network access and credentials for the registry hosting ref, so it does not
// run in the offline tests. Auth comes from the ambient Docker keychain.
func Pull(ref string) (v1.Image, error) {
	return pull(context.Background(), ref)
}

func pull(ctx context.Context, ref string) (v1.Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("oci: parsing reference %q: %w", ref, err)
	}
	img, err := remote.Image(r,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("oci: pulling %q (needs registry access): %w", ref, err)
	}
	return img, nil
}

// Bundle pulls every reference and writes the images into an OCI layout at dir.
// It is the real end-to-end path and needs registry access, bounded by
// pullTimeout so an unreachable registry fails cleanly. To build a layout
// offline (tests), call WriteLayout directly with in-memory images.
func Bundle(dir string, refs []string) ([]Pulled, error) {
	// The context spans pulling and layout writing (layer blobs are fetched
	// lazily during WriteLayout), so it is cancelled only once both finish.
	ctx, cancel := context.WithTimeout(context.Background(), pullTimeout)
	defer cancel()

	imgs := make(map[string]v1.Image, len(refs))
	for _, ref := range refs {
		img, err := pull(ctx, ref)
		if err != nil {
			return nil, err
		}
		imgs[ref] = img
	}
	return WriteLayout(dir, imgs)
}

// WriteLayout writes an OCI image layout to dir containing the given images,
// keyed by reference. It returns one Pulled per image (sorted by reference)
// carrying the image's content-addressed digest. The images may be fetched with
// Pull or constructed in memory; WriteLayout itself needs no network.
func WriteLayout(dir string, images map[string]v1.Image) ([]Pulled, error) {
	if len(images) == 0 {
		return nil, nil
	}
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		return nil, fmt.Errorf("oci: initializing layout at %s: %w", dir, err)
	}

	refs := make([]string, 0, len(images))
	for ref := range images {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	out := make([]Pulled, 0, len(images))
	for _, ref := range refs {
		img := images[ref]
		dg, err := img.Digest()
		if err != nil {
			return nil, fmt.Errorf("oci: digesting %q: %w", ref, err)
		}
		if err := p.AppendImage(img, layout.WithAnnotations(map[string]string{
			refAnnotation: ref,
		})); err != nil {
			return nil, fmt.Errorf("oci: writing %q into layout: %w", ref, err)
		}
		out = append(out, Pulled{Reference: ref, Digest: dg.String()})
	}
	return out, nil
}

// VerifyLayout opens the OCI layout at dir and confirms every digest in
// wantDigests resolves to an image whose manifest, config, and layer blobs all
// re-hash to their recorded digests. Because OCI is content-addressed, a
// tampered blob changes a computed digest and fails this check.
func VerifyLayout(dir string, wantDigests []string) error {
	p, err := layout.FromPath(dir)
	if err != nil {
		return fmt.Errorf("oci: opening layout at %s: %w", dir, err)
	}
	idx, err := p.ImageIndex()
	if err != nil {
		return fmt.Errorf("oci: reading image index: %w", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return fmt.Errorf("oci: reading index manifest: %w", err)
	}
	present := make(map[string]bool, len(manifest.Manifests))
	for _, desc := range manifest.Manifests {
		present[desc.Digest.String()] = true
	}

	for _, want := range wantDigests {
		if !present[want] {
			return fmt.Errorf("oci: image %s is missing from the layout", want)
		}
		h, err := v1.NewHash(want)
		if err != nil {
			return fmt.Errorf("oci: invalid digest %q: %w", want, err)
		}
		img, err := idx.Image(h)
		if err != nil {
			return fmt.Errorf("oci: loading image %s: %w", want, err)
		}
		got, err := img.Digest()
		if err != nil {
			return fmt.Errorf("oci: digesting image %s: %w", want, err)
		}
		if got.String() != want {
			return fmt.Errorf("oci: image %s manifest digest mismatch (got %s) — layout tampered", want, got)
		}
		if err := validate.Image(img); err != nil {
			return fmt.Errorf("oci: image %s failed content validation — layout tampered: %w", want, err)
		}
	}
	return nil
}
