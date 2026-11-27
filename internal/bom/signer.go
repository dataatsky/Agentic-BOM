package bom

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const PayloadTypeCycloneDX = "application/vnd.cyclonedx+json"

// DSSEEnvelope follows the Dead Simple Signing Envelope specification.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"` // base64-encoded payload
	Signatures  []DSSESignature `json:"signatures"`
}

type DSSESignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"` // base64-encoded Ed25519 signature
}

// GenerateKeyPair creates a fresh Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// pae computes DSSE Pre-Authentication Encoding:
// "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
func pae(payloadType string, payload []byte) []byte {
	header := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out
}

// SignPayload wraps payload in an Ed25519-signed DSSE envelope.
func SignPayload(payloadType string, payload []byte, priv ed25519.PrivateKey) (*DSSEEnvelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	if payloadType == "" {
		return nil, errors.New("payloadType must not be empty")
	}
	sig := ed25519.Sign(priv, pae(payloadType, payload))
	return &DSSEEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{
			{
				KeyID: "agbom-gate-ed25519",
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}, nil
}

// VerifyEnvelope checks that:
// 1. The DSSE envelope payload matches expectedPayload byte-for-byte.
// 2. At least one signature verifies against pub over PAE(payloadType, expectedPayload).
func VerifyEnvelope(env *DSSEEnvelope, expectedPayload []byte, pub ed25519.PublicKey) error {
	if env == nil {
		return errors.New("nil dsse envelope")
	}
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key size")
	}
	if env.PayloadType == "" {
		return errors.New("dsse envelope missing payloadType")
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("decode envelope payload: %w", err)
	}
	if !bytes.Equal(decodedPayload, expectedPayload) {
		return errors.New("agbom payload mismatch against signed dsse envelope")
	}
	if len(env.Signatures) == 0 {
		return errors.New("dsse envelope contains no signatures")
	}
	msg := pae(env.PayloadType, expectedPayload)
	for _, s := range env.Signatures {
		rawSig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if len(rawSig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, rawSig) {
			return nil
		}
	}
	return errors.New("ed25519 signature verification failed")
}

// EncodeKey encodes raw key bytes to base64 text.
func EncodeKey(key []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(key) + "\n")
}

// DecodeKey decodes a base64-encoded key file.
func DecodeKey(raw []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
}

func MarshalEnvelope(env *DSSEEnvelope) ([]byte, error) {
	return json.MarshalIndent(env, "", "  ")
}
