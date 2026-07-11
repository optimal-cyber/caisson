package signing

import "testing"

func TestSignVerifyRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("sealed manifest bytes")
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Verify(msg, sig) {
		t.Fatal("valid signature did not verify")
	}
	if k.Verify([]byte("tampered"), sig) {
		t.Fatal("signature verified over tampered message")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	k, _ := Generate()
	privPEM, err := k.PrivatePEM()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := k.PublicPEM()
	if err != nil {
		t.Fatal(err)
	}
	loadedPriv, err := LoadPrivate(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	loadedPub, err := LoadPublic(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPriv.KeyID() != k.KeyID() || loadedPub.KeyID() != k.KeyID() {
		t.Fatal("key id changed across PEM round-trip")
	}
	// A signature from the loaded private key verifies with the loaded public key.
	sig, _ := loadedPriv.Sign([]byte("x"))
	if !loadedPub.Verify([]byte("x"), sig) {
		t.Fatal("cross-loaded key failed to verify")
	}
}

func TestDSSERoundTrip(t *testing.T) {
	k, _ := Generate()
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	env, err := k.WrapDSSE(stmt)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := k.VerifyDSSE(env)
	if !ok {
		t.Fatal("DSSE envelope did not verify")
	}
	if string(payload) != string(stmt) {
		t.Fatalf("payload round-trip mismatch: %s", payload)
	}
	// Tampering the payload breaks verification.
	env.Payload = env.Payload[:len(env.Payload)-4] + "AAAA"
	if _, ok := k.VerifyDSSE(env); ok {
		t.Fatal("DSSE verified over tampered payload")
	}
}
