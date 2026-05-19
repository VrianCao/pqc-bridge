from __future__ import annotations

import json

import pqcb


kem_public_key, kem_secret_key = pqcb.kem_keypair()
ciphertext, encapsulated = pqcb.kem_encapsulate(kem_public_key)
decapsulated = pqcb.kem_decapsulate(kem_secret_key, ciphertext)

if encapsulated != decapsulated:
    raise RuntimeError("ML-KEM shared secrets did not match")

signature_public_key, signature_secret_key = pqcb.signature_keypair()
message = b"pqcb python primitive smoke"
signature = pqcb.sign(signature_secret_key, message)
pqcb.verify(signature_public_key, message, signature)

try:
    pqcb.verify(signature_public_key, b"tampered", signature)
    raise RuntimeError("tampered ML-DSA signature unexpectedly verified")
except pqcb.VerificationFailedError:
    pass

print(
    json.dumps(
        {
            "kemSharedSecretLength": len(encapsulated),
            "signatureLength": len(signature),
            "tamperedSignatureRejected": True,
        },
        sort_keys=True,
    )
)
