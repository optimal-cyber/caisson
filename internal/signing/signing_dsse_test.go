package signing

import (
	"encoding/base64"
	"testing"
)

func TestPAEMatchesDSSESpec(t *testing.T) {
	// DSSEv1 SP LEN(type) SP type SP LEN(body) SP body
	if got, want := string(pae("t", []byte("body"))), "DSSEv1 1 t 4 body"; got != want {
		t.Errorf("PAE = %q, want %q", got, want)
	}
	if got, want := string(pae("x", nil)), "DSSEv1 1 x 0 "; got != want {
		t.Errorf("empty-body PAE = %q, want %q", got, want)
	}
}

func TestDSSEEnvelopeIsCosignShaped(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}`)

	env, err := key.WrapDSSE(stmt)
	if err != nil {
		t.Fatalf("WrapDSSE: %v", err)
	}

	// cosign/in-toto shape.
	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("payloadType = %q, want application/vnd.in-toto+json", env.PayloadType)
	}
	dec, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || string(dec) != string(stmt) {
		t.Errorf("payload does not round-trip: %v", err)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].Sig == "" {
		t.Fatalf("expected one non-empty signature, got %+v", env.Signatures)
	}

	// Verifies with the signing key, round-tripping the statement.
	payload, ok := key.VerifyDSSE(env)
	if !ok || string(payload) != string(stmt) {
		t.Error("VerifyDSSE failed to round-trip a valid envelope")
	}
	// Fails with an unrelated key.
	other, _ := Generate()
	if _, ok := other.VerifyDSSE(env); ok {
		t.Error("envelope verified against the wrong key")
	}
	// Fails when the payload is tampered (signature is over the PAE of the payload).
	env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"_type":"tampered"}`))
	if _, ok := key.VerifyDSSE(env); ok {
		t.Error("a tampered payload still verified")
	}
}
