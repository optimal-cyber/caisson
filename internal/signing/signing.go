// Package signing provides Ed25519 key generation, signing, and verification for
// Caisson vaults, plus DSSE (Dead Simple Signing Envelope) construction so
// attestations can be signed with the same key. Standard-library crypto only —
// no external signing service required, so it works fully disconnected.
//
// This is Caisson-native signing. Sigstore/cosign interoperability (keyless
// Fulcio/Rekor, transparency logs) is a documented follow-on; the on-disk
// formats chosen here (PKCS#8/PKIX PEM keys, DSSE envelopes, in-toto statements)
// are deliberately standard so that migration stays clean.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// Key wraps an Ed25519 keypair. Either half may be nil (a public-only key can
// verify but not sign).
type Key struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Generate creates a new Ed25519 keypair.
func Generate() (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{Private: priv, Public: pub}, nil
}

// PrivatePEM encodes the private key as a PKCS#8 PEM block.
func (k *Key) PrivatePEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// PublicPEM encodes the public key as a PKIX PEM block.
func (k *Key) PublicPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadPrivate parses a PKCS#8 PEM private key.
func LoadPrivate(pemBytes []byte) (*Key, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("signing: no PEM block in private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing: not an Ed25519 private key (%T)", parsed)
	}
	return &Key{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

// LoadPublic parses a PKIX PEM public key.
func LoadPublic(pemBytes []byte) (*Key, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("signing: no PEM block in public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing: not an Ed25519 public key (%T)", parsed)
	}
	return &Key{Public: pub}, nil
}

// KeyID is a stable identifier: the SHA-256 of the public key, hex-encoded.
func (k *Key) KeyID() string {
	sum := sha256.Sum256(k.Public)
	return fmt.Sprintf("%x", sum[:])
}

// Sign signs a message with the private key.
func (k *Key) Sign(msg []byte) ([]byte, error) {
	if k.Private == nil {
		return nil, errors.New("signing: no private key available")
	}
	return ed25519.Sign(k.Private, msg), nil
}

// Verify checks a signature against the public key.
func (k *Key) Verify(msg, sig []byte) bool {
	if k.Public == nil {
		return false
	}
	return ed25519.Verify(k.Public, msg, sig)
}

// --- DSSE (Dead Simple Signing Envelope) --------------------------------------

// DSSEPayloadType is the media type for in-toto statement payloads.
const DSSEPayloadType = "application/vnd.in-toto+json"

// Envelope is a DSSE envelope over an in-toto statement.
type Envelope struct {
	PayloadType string        `json:"payloadType"`
	Payload     string        `json:"payload"` // base64 of the statement bytes
	Signatures  []EnvelopeSig `json:"signatures"`
}

// EnvelopeSig is one signature over a DSSE envelope's PAE.
type EnvelopeSig struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64 of Sign(PAE)
}

// WrapDSSE signs raw statement bytes into a DSSE envelope.
func (k *Key) WrapDSSE(statement []byte) (*Envelope, error) {
	sig, err := k.Sign(pae(DSSEPayloadType, statement))
	if err != nil {
		return nil, err
	}
	return &Envelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(statement),
		Signatures:  []EnvelopeSig{{KeyID: k.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// VerifyDSSE checks an envelope's signatures against the key and returns the
// decoded statement payload and whether a signature verified.
func (k *Key) VerifyDSSE(e *Envelope) (payload []byte, ok bool) {
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, false
	}
	msg := pae(e.PayloadType, payload)
	for _, s := range e.Signatures {
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if k.Verify(msg, raw) {
			return payload, true
		}
	}
	return payload, false
}

// pae implements the DSSE Pre-Authentication Encoding:
//
//	"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), string(payload)))
}
