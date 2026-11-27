package bom

import "testing"

func TestDSSESignAndTamperFailsClosed(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	payload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	env, err := SignPayload(PayloadTypeCycloneDX, payload, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyEnvelope(env, payload, pub); err != nil {
		t.Fatalf("expected valid signature to pass, got: %v", err)
	}

	tampered := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)
	if err := VerifyEnvelope(env, tampered, pub); err == nil {
		t.Fatal("expected tampered AgBOM payload to fail verification")
	}
}

func TestDSSEWrongKeyFailsClosed(t *testing.T) {
	_, priv1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen 1: %v", err)
	}
	pub2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen 2: %v", err)
	}
	payload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	env, err := SignPayload(PayloadTypeCycloneDX, payload, priv1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyEnvelope(env, payload, pub2); err == nil {
		t.Fatal("expected verification against wrong public key to fail")
	}
}
