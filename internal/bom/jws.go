package bom

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/secops/agbom-gate/internal/canon"
)

// A2ASignature represents an A2A Agent Card JWS signature entry (detached JWS over RFC 8785 JCS payload).
type A2ASignature struct {
	Protected string         `json:"protected"`
	Signature string         `json:"signature"`
	Header    map[string]any `json:"header,omitempty"`
}

// LoadJWSVerifyKey parses a public key from PEM (PKIX), JWK JSON (OKP/Ed25519 or EC/P-256),
// or raw base64-encoded Ed25519 public key bytes.
func LoadJWSVerifyKey(raw []byte) (crypto.PublicKey, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("empty public key")
	}

	// 1. PEM PKIX public key
	if strings.HasPrefix(trimmed, "-----BEGIN ") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, errors.New("invalid PEM public key block")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		switch pub.(type) {
		case ed25519.PublicKey, *ecdsa.PublicKey:
			return pub, nil
		default:
			return nil, fmt.Errorf("unsupported JWS public key type %T (supported: Ed25519, ECDSA P-256)", pub)
		}
	}

	// 2. JWK JSON
	if strings.HasPrefix(trimmed, "{") {
		var jwk struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		if err := json.Unmarshal([]byte(trimmed), &jwk); err != nil {
			return nil, fmt.Errorf("parse JWK: %w", err)
		}
		switch jwk.Kty {
		case "OKP":
			if jwk.Crv != "Ed25519" {
				return nil, fmt.Errorf("unsupported OKP curve %q", jwk.Crv)
			}
			xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil || len(xb) != ed25519.PublicKeySize {
				return nil, errors.New("invalid Ed25519 JWK x coordinate")
			}
			return ed25519.PublicKey(xb), nil
		case "EC":
			if jwk.Crv != "P-256" {
				return nil, fmt.Errorf("unsupported EC curve %q", jwk.Crv)
			}
			xb, err1 := base64.RawURLEncoding.DecodeString(jwk.X)
			yb, err2 := base64.RawURLEncoding.DecodeString(jwk.Y)
			if err1 != nil || err2 != nil || len(xb) == 0 || len(yb) == 0 {
				return nil, errors.New("invalid P-256 JWK coordinates")
			}
			pub := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xb),
				Y:     new(big.Int).SetBytes(yb),
			}
			if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
				return nil, errors.New("P-256 JWK point is not on curve")
			}
			return pub, nil
		default:
			return nil, fmt.Errorf("unsupported JWK kty %q", jwk.Kty)
		}
	}

	// 3. Raw base64 Ed25519 key (standard agbom.pub format)
	keyBytes, err := DecodeKey([]byte(trimmed))
	if err != nil {
		return nil, fmt.Errorf("decode base64 public key: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected raw public key length %d (expected %d for Ed25519)", len(keyBytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(keyBytes), nil
}

// VerifyCompactJWS verifies an RFC 7515 compact JWS ("protected.payload.signature")
// using EdDSA (Ed25519) or ES256 (ECDSA P-256) and returns the decoded payload bytes.
func VerifyCompactJWS(compact string, pub crypto.PublicKey) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid compact JWS format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode compact JWS payload: %w", err)
	}
	if err := verifyJWSSigningInput(parts[0], parts[0]+"."+parts[1], parts[2], pub); err != nil {
		return nil, err
	}
	return payload, nil
}

// VerifyA2ACardJWS checks the JWS signatures embedded in an A2A Agent Card JSON object.
// Per A2A specification, signatures cover the RFC 8785 JCS canonical bytes of the card
// excluding the top-level "signatures" field: signingInput = protected + "." + base64url(JCS(cardWithoutSigs)).
// Returns:
//   - canonicalBytes: RFC 8785 JCS bytes of the card without "signatures"
//   - status: "verified", "unsigned", or "invalid"
func VerifyA2ACardJWS(rawCard []byte, pub crypto.PublicKey) (canonicalBytes []byte, status string, err error) {
	trimmed := strings.TrimSpace(string(rawCard))
	// Support compact JWS-wrapped Agent Card directly.
	if !strings.HasPrefix(trimmed, "{") && strings.Count(trimmed, ".") == 2 {
		if pub == nil {
			parts := strings.Split(trimmed, ".")
			payload, decErr := base64.RawURLEncoding.DecodeString(parts[1])
			if decErr != nil {
				return nil, "invalid", fmt.Errorf("invalid compact JWS card: %w", decErr)
			}
			jcsBytes, jcsErr := canon.JCS(payload)
			if jcsErr != nil {
				return nil, "invalid", jcsErr
			}
			return jcsBytes, "invalid", errors.New("no A2A public key configured to verify compact JWS")
		}
		payload, vErr := VerifyCompactJWS(trimmed, pub)
		if vErr != nil {
			return nil, "invalid", vErr
		}
		jcsBytes, jcsErr := canon.JCS(payload)
		if jcsErr != nil {
			return nil, "invalid", jcsErr
		}
		return jcsBytes, "verified", nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(rawCard, &obj); err != nil {
		return nil, "invalid", fmt.Errorf("unmarshal A2A agent card: %w", err)
	}

	var sigs []A2ASignature
	if sigRaw, hasSigs := obj["signatures"]; hasSigs {
		if err := json.Unmarshal(sigRaw, &sigs); err != nil {
			return nil, "invalid", fmt.Errorf("parse A2A card signatures: %w", err)
		}
		delete(obj, "signatures")
	}

	withoutSigs, err := json.Marshal(obj)
	if err != nil {
		return nil, "invalid", err
	}
	canonicalBytes, err = canon.JCS(withoutSigs)
	if err != nil {
		return nil, "invalid", fmt.Errorf("canonicalize A2A card: %w", err)
	}

	if len(sigs) == 0 {
		return canonicalBytes, "unsigned", nil
	}
	if pub == nil {
		return canonicalBytes, "invalid", errors.New("A2A card is signed but no --a2a-pub-key was supplied")
	}

	b64Payload := base64.RawURLEncoding.EncodeToString(canonicalBytes)
	var lastErr error
	for _, s := range sigs {
		signingInput := s.Protected + "." + b64Payload
		if err := verifyJWSSigningInput(s.Protected, signingInput, s.Signature, pub); err == nil {
			return canonicalBytes, "verified", nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no valid A2A JWS signature matched")
	}
	return canonicalBytes, "invalid", lastErr
}

// SignA2ACardEd25519 signs an A2A Agent Card JSON object with Ed25519 (alg: "EdDSA")
// and embeds the detached JWS signature inside the top-level "signatures" array.
func SignA2ACardEd25519(rawCard []byte, priv ed25519.PrivateKey, keyID string) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	obj, canonical, err := stripAndCanonicalizeA2ACard(rawCard)
	if err != nil {
		return nil, err
	}
	hdr := map[string]string{"alg": "EdDSA"}
	if keyID != "" {
		hdr["kid"] = keyID
	}
	hdrBytes, _ := json.Marshal(hdr)
	b64Protected := base64.RawURLEncoding.EncodeToString(hdrBytes)
	b64Payload := base64.RawURLEncoding.EncodeToString(canonical)
	sig := ed25519.Sign(priv, []byte(b64Protected+"."+b64Payload))

	sigEntry := []A2ASignature{{
		Protected: b64Protected,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}}
	sigJSON, _ := json.Marshal(sigEntry)
	obj["signatures"] = sigJSON
	return json.MarshalIndent(obj, "", "  ")
}

// SignA2ACardES256 signs an A2A Agent Card JSON object with ECDSA P-256 (alg: "ES256")
// using IEEE P1363 64-byte (r || s) JWS encoding.
func SignA2ACardES256(rawCard []byte, priv *ecdsa.PrivateKey, keyID string) ([]byte, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errors.New("ES256 requires a P-256 ECDSA private key")
	}
	obj, canonical, err := stripAndCanonicalizeA2ACard(rawCard)
	if err != nil {
		return nil, err
	}
	hdr := map[string]string{"alg": "ES256"}
	if keyID != "" {
		hdr["kid"] = keyID
	}
	hdrBytes, _ := json.Marshal(hdr)
	b64Protected := base64.RawURLEncoding.EncodeToString(hdrBytes)
	b64Payload := base64.RawURLEncoding.EncodeToString(canonical)
	digest := sha256.Sum256([]byte(b64Protected + "." + b64Payload))

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	rawSig := make([]byte, 64)
	r.FillBytes(rawSig[:32])
	s.FillBytes(rawSig[32:])

	sigEntry := []A2ASignature{{
		Protected: b64Protected,
		Signature: base64.RawURLEncoding.EncodeToString(rawSig),
	}}
	sigJSON, _ := json.Marshal(sigEntry)
	obj["signatures"] = sigJSON
	return json.MarshalIndent(obj, "", "  ")
}

func stripAndCanonicalizeA2ACard(rawCard []byte) (map[string]json.RawMessage, []byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(rawCard, &obj); err != nil {
		return nil, nil, err
	}
	delete(obj, "signatures")
	withoutSigs, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := canon.JCS(withoutSigs)
	if err != nil {
		return nil, nil, err
	}
	return obj, canonical, nil
}

func verifyJWSSigningInput(b64Protected, signingInput, b64Sig string, pub crypto.PublicKey) error {
	hdrBytes, err := base64.RawURLEncoding.DecodeString(b64Protected)
	if err != nil {
		return fmt.Errorf("decode JWS protected header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return fmt.Errorf("parse JWS protected header: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(b64Sig)
	if err != nil {
		return fmt.Errorf("decode JWS signature: %w", err)
	}

	switch hdr.Alg {
	case "EdDSA":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("JWS alg EdDSA requires Ed25519 public key, got %T", pub)
		}
		if len(sigBytes) != ed25519.SignatureSize || !ed25519.Verify(edPub, []byte(signingInput), sigBytes) {
			return errors.New("EdDSA JWS signature verification failed")
		}
		return nil
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return fmt.Errorf("JWS alg ES256 requires P-256 ECDSA public key, got %T", pub)
		}
		if len(sigBytes) != 64 {
			return fmt.Errorf("invalid ES256 signature length %d (expected 64)", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		digest := sha256.Sum256([]byte(signingInput))
		if !ecdsa.Verify(ecPub, digest[:], r, s) {
			return errors.New("ES256 JWS signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported or unsafe JWS alg %q (supported: EdDSA, ES256)", hdr.Alg)
	}
}
