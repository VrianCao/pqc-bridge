package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/VrianCao/pqc-bridge/bindings/go/pqcb"
)

func main() {
	fmt.Printf("PQC Bridge %s\n", pqcb.Version())

	kemAvailable, err := pqcb.BackendAvailable("ML-KEM-768")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ML-KEM-768 available: %t\n", kemAvailable)

	signatureAvailable, err := pqcb.BackendAvailable("ML-DSA-65")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ML-DSA-65 available: %t\n", signatureAvailable)

	kemKeypair, err := pqcb.KEMKeypairGenerate()
	if err != nil {
		log.Fatal(err)
	}
	encapsulation, err := pqcb.KEMEncapsulate(kemKeypair.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	decapsulated, err := pqcb.KEMDecapsulate(kemKeypair.SecretKey, encapsulation.Ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(encapsulation.SharedSecret, decapsulated) {
		log.Fatal("ML-KEM shared secrets did not match")
	}

	signatureKeypair, err := pqcb.SignatureKeypairGenerate()
	if err != nil {
		log.Fatal(err)
	}
	message := []byte("pqcb go example")
	signature, err := pqcb.Sign(signatureKeypair.SecretKey, message)
	if err != nil {
		log.Fatal(err)
	}
	if err := pqcb.Verify(signatureKeypair.PublicKey, message, signature); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Go primitive example completed")
}
