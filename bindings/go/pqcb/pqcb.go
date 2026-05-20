// Package pqcb provides Go bindings for PQC Bridge.
package pqcb

/*
#cgo linux LDFLAGS: -L${SRCDIR}/../../../target/debug -Wl,-rpath,${SRCDIR}/../../../target/debug -lpqcb_ffi
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../target/debug -Wl,-rpath,${SRCDIR}/../../../target/debug -lpqcb_ffi
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	const uint8_t *data;
	size_t len;
} PqcbBuffer;

typedef struct {
	uint8_t *data;
	size_t len;
} PqcbOwnedBuffer;

typedef struct {
	uint16_t major;
	uint16_t minor;
	uint16_t patch;
} PqcbVersion;

extern PqcbVersion pqcb_version(void);
extern uint16_t pqcb_abi_version_major(void);
extern uint32_t pqcb_backend_available(uint32_t algorithm_id, bool *available);
extern uint32_t pqcb_ml_kem_768_keypair(PqcbOwnedBuffer *public_key_out, PqcbOwnedBuffer *secret_key_out);
extern uint32_t pqcb_ml_kem_768_encapsulate(PqcbBuffer public_key, PqcbOwnedBuffer *ciphertext_out, PqcbOwnedBuffer *shared_secret_out);
extern uint32_t pqcb_ml_kem_768_decapsulate(PqcbBuffer secret_key, PqcbBuffer ciphertext, PqcbOwnedBuffer *shared_secret_out);
extern uint32_t pqcb_ml_dsa_65_keypair(PqcbOwnedBuffer *public_key_out, PqcbOwnedBuffer *secret_key_out);
extern uint32_t pqcb_ml_dsa_65_sign(PqcbBuffer secret_key, PqcbBuffer message, PqcbOwnedBuffer *signature_out);
extern uint32_t pqcb_ml_dsa_65_verify(PqcbBuffer public_key, PqcbBuffer message, PqcbBuffer signature_bytes);
extern void pqcb_buffer_free(PqcbOwnedBuffer buffer);
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// PackageVersion is the Go binding package version.
const PackageVersion = "0.1.0"

const (
	statusOK                 = 0
	statusNullPointer        = 1
	statusInvalidLength      = 2
	statusInvalidAlgorithm   = 3
	statusBackendUnavailable = 4
	statusVerificationFailed = 5
	statusCryptoFailure      = 6
	statusPanic              = 255

	mlKem768 = 1
	mlDsa65  = 2

	supportedABIMajor = 1
)

// Sentinel errors used by Error.Unwrap.
var (
	ErrNullPointer        = errors.New("pqcb null pointer")
	ErrInvalidLength      = errors.New("pqcb invalid length")
	ErrInvalidAlgorithm   = errors.New("pqcb invalid algorithm")
	ErrBackendUnavailable = errors.New("pqcb backend unavailable")
	ErrVerificationFailed = errors.New("pqcb verification failed")
	ErrCryptoFailure      = errors.New("pqcb cryptographic operation failed")
	ErrPanic              = errors.New("pqcb panic caught at FFI boundary")
	ErrUnsupportedABI     = errors.New("pqcb unsupported C ABI major version")
)

// Error wraps deterministic ABI error identity with operation context.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string {
	return e.Op + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error {
	return e.Err
}

// KEMKeypair contains an ML-KEM-768 public and secret key.
type KEMKeypair struct {
	PublicKey []byte
	SecretKey []byte
}

// Encapsulation contains an ML-KEM-768 ciphertext and shared secret.
type Encapsulation struct {
	Ciphertext   []byte
	SharedSecret []byte
}

// SignatureKeypair contains an ML-DSA-65 public and secret key.
type SignatureKeypair struct {
	PublicKey []byte
	SecretKey []byte
}

// Version returns the ABI-backed PQC Bridge crate version.
func Version() string {
	version := C.pqcb_version()
	return fmt.Sprintf("%d.%d.%d", version.major, version.minor, version.patch)
}

// ABIMajorVersion returns the loaded C ABI major version.
func ABIMajorVersion() uint16 {
	return uint16(C.pqcb_abi_version_major())
}

// BackendAvailable reports whether the native backend supports algorithm.
func BackendAvailable(algorithm string) (bool, error) {
	algorithmID, err := algorithmID(algorithm)
	if err != nil {
		return false, err
	}
	if err := checkABIMajor("backend availability"); err != nil {
		return false, err
	}

	var available C.bool
	status := C.pqcb_backend_available(C.uint32_t(algorithmID), &available)
	if err := errorFromStatus(status, "backend availability"); err != nil {
		return false, err
	}

	return bool(available), nil
}

// KEMKeypairGenerate generates an ML-KEM-768 keypair.
func KEMKeypairGenerate() (KEMKeypair, error) {
	if err := checkABIMajor("ML-KEM-768 keypair"); err != nil {
		return KEMKeypair{}, err
	}
	var publicKey C.PqcbOwnedBuffer
	var secretKey C.PqcbOwnedBuffer
	status := C.pqcb_ml_kem_768_keypair(&publicKey, &secretKey)
	if err := errorFromStatus(status, "ML-KEM-768 keypair"); err != nil {
		return KEMKeypair{}, err
	}

	publicKeyBytes, err := takeOwnedBuffer(publicKey)
	if err != nil {
		return KEMKeypair{}, err
	}
	secretKeyBytes, err := takeOwnedBuffer(secretKey)
	if err != nil {
		return KEMKeypair{}, err
	}

	return KEMKeypair{
		PublicKey: publicKeyBytes,
		SecretKey: secretKeyBytes,
	}, nil
}

// KEMEncapsulate encapsulates an ML-KEM-768 shared secret for publicKey.
func KEMEncapsulate(publicKey []byte) (Encapsulation, error) {
	if err := checkABIMajor("ML-KEM-768 encapsulate"); err != nil {
		return Encapsulation{}, err
	}
	var ciphertext C.PqcbOwnedBuffer
	var sharedSecret C.PqcbOwnedBuffer
	status := C.pqcb_ml_kem_768_encapsulate(
		borrow(publicKey),
		&ciphertext,
		&sharedSecret,
	)
	if err := errorFromStatus(status, "ML-KEM-768 encapsulate"); err != nil {
		return Encapsulation{}, err
	}

	ciphertextBytes, err := takeOwnedBuffer(ciphertext)
	if err != nil {
		return Encapsulation{}, err
	}
	sharedSecretBytes, err := takeOwnedBuffer(sharedSecret)
	if err != nil {
		return Encapsulation{}, err
	}

	return Encapsulation{
		Ciphertext:   ciphertextBytes,
		SharedSecret: sharedSecretBytes,
	}, nil
}

// KEMDecapsulate decapsulates an ML-KEM-768 shared secret.
func KEMDecapsulate(secretKey []byte, ciphertext []byte) ([]byte, error) {
	if err := checkABIMajor("ML-KEM-768 decapsulate"); err != nil {
		return nil, err
	}
	var sharedSecret C.PqcbOwnedBuffer
	status := C.pqcb_ml_kem_768_decapsulate(
		borrow(secretKey),
		borrow(ciphertext),
		&sharedSecret,
	)
	if err := errorFromStatus(status, "ML-KEM-768 decapsulate"); err != nil {
		return nil, err
	}

	return takeOwnedBuffer(sharedSecret)
}

// SignatureKeypairGenerate generates an ML-DSA-65 keypair.
func SignatureKeypairGenerate() (SignatureKeypair, error) {
	if err := checkABIMajor("ML-DSA-65 keypair"); err != nil {
		return SignatureKeypair{}, err
	}
	var publicKey C.PqcbOwnedBuffer
	var secretKey C.PqcbOwnedBuffer
	status := C.pqcb_ml_dsa_65_keypair(&publicKey, &secretKey)
	if err := errorFromStatus(status, "ML-DSA-65 keypair"); err != nil {
		return SignatureKeypair{}, err
	}

	publicKeyBytes, err := takeOwnedBuffer(publicKey)
	if err != nil {
		return SignatureKeypair{}, err
	}
	secretKeyBytes, err := takeOwnedBuffer(secretKey)
	if err != nil {
		return SignatureKeypair{}, err
	}

	return SignatureKeypair{
		PublicKey: publicKeyBytes,
		SecretKey: secretKeyBytes,
	}, nil
}

// Sign signs message with an ML-DSA-65 secret key.
func Sign(secretKey []byte, message []byte) ([]byte, error) {
	if err := checkABIMajor("ML-DSA-65 sign"); err != nil {
		return nil, err
	}
	var signature C.PqcbOwnedBuffer
	status := C.pqcb_ml_dsa_65_sign(
		borrow(secretKey),
		borrow(message),
		&signature,
	)
	if err := errorFromStatus(status, "ML-DSA-65 sign"); err != nil {
		return nil, err
	}

	return takeOwnedBuffer(signature)
}

// Verify verifies an ML-DSA-65 signature.
func Verify(publicKey []byte, message []byte, signature []byte) error {
	if err := checkABIMajor("ML-DSA-65 verify"); err != nil {
		return err
	}
	status := C.pqcb_ml_dsa_65_verify(
		borrow(publicKey),
		borrow(message),
		borrow(signature),
	)
	return errorFromStatus(status, "ML-DSA-65 verify")
}

func checkABIMajor(operation string) error {
	if ABIMajorVersion() != supportedABIMajor {
		return &Error{Op: operation, Err: ErrUnsupportedABI}
	}
	return nil
}

func algorithmID(algorithm string) (uint32, error) {
	switch algorithm {
	case "ML-KEM-768":
		return mlKem768, nil
	case "ML-DSA-65":
		return mlDsa65, nil
	default:
		return 0, &Error{Op: "algorithm lookup", Err: ErrInvalidAlgorithm}
	}
}

func borrow(data []byte) C.PqcbBuffer {
	if len(data) == 0 {
		return C.PqcbBuffer{}
	}

	return C.PqcbBuffer{
		data: (*C.uint8_t)(unsafe.Pointer(&data[0])),
		len:  C.size_t(len(data)),
	}
}

func takeOwnedBuffer(buffer C.PqcbOwnedBuffer) ([]byte, error) {
	if buffer.data == nil || buffer.len == 0 {
		return nil, &Error{Op: "owned buffer", Err: ErrNullPointer}
	}
	defer C.pqcb_buffer_free(buffer)

	return C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len)), nil
}

func errorFromStatus(status C.uint32_t, operation string) error {
	switch uint32(status) {
	case statusOK:
		return nil
	case statusNullPointer:
		return &Error{Op: operation, Err: ErrNullPointer}
	case statusInvalidLength:
		return &Error{Op: operation, Err: ErrInvalidLength}
	case statusInvalidAlgorithm:
		return &Error{Op: operation, Err: ErrInvalidAlgorithm}
	case statusBackendUnavailable:
		return &Error{Op: operation, Err: ErrBackendUnavailable}
	case statusVerificationFailed:
		return &Error{Op: operation, Err: ErrVerificationFailed}
	case statusCryptoFailure:
		return &Error{Op: operation, Err: ErrCryptoFailure}
	case statusPanic:
		return &Error{Op: operation, Err: ErrPanic}
	default:
		return &Error{Op: operation, Err: ErrCryptoFailure}
	}
}
