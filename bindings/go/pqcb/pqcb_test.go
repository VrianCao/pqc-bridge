package pqcb

import (
	"bytes"
	"errors"
	"testing"
)

func TestVersionAndAvailability(t *testing.T) {
	if got := Version(); got != "0.2.0" {
		t.Fatalf("Version() = %q, want 0.2.0", got)
	}
	if got := ABIMajorVersion(); got != supportedABIMajor {
		t.Fatalf("ABIMajorVersion() = %d, want %d", got, supportedABIMajor)
	}

	available, err := BackendAvailable("ML-KEM-768")
	if err != nil {
		t.Fatalf("BackendAvailable(ML-KEM-768): %v", err)
	}
	if !available {
		t.Fatal("ML-KEM-768 backend is not available")
	}

	available, err = BackendAvailable("ML-DSA-65")
	if err != nil {
		t.Fatalf("BackendAvailable(ML-DSA-65): %v", err)
	}
	if !available {
		t.Fatal("ML-DSA-65 backend is not available")
	}

	_, err = BackendAvailable("unknown")
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Fatalf("BackendAvailable(unknown) error = %v, want ErrInvalidAlgorithm", err)
	}
}

func TestKEMRoundTrip(t *testing.T) {
	keypair, err := KEMKeypairGenerate()
	if err != nil {
		t.Fatalf("KEMKeypairGenerate: %v", err)
	}

	encapsulation, err := KEMEncapsulate(keypair.PublicKey)
	if err != nil {
		t.Fatalf("KEMEncapsulate: %v", err)
	}

	decapsulated, err := KEMDecapsulate(keypair.SecretKey, encapsulation.Ciphertext)
	if err != nil {
		t.Fatalf("KEMDecapsulate: %v", err)
	}

	if !bytes.Equal(encapsulation.SharedSecret, decapsulated) {
		t.Fatal("ML-KEM shared secrets did not match")
	}
}

func TestSignatureRoundTripAndTamper(t *testing.T) {
	keypair, err := SignatureKeypairGenerate()
	if err != nil {
		t.Fatalf("SignatureKeypairGenerate: %v", err)
	}

	message := []byte("pqcb go primitive smoke")
	signature, err := Sign(keypair.SecretKey, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := Verify(keypair.PublicKey, message, signature); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if err := Verify(keypair.PublicKey, []byte("tampered"), signature); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("Verify(tampered) error = %v, want ErrVerificationFailed", err)
	}
}
