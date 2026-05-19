from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pqcb


print(f"PQC Bridge {pqcb.abi_version()}")
print(f"ML-KEM-768 available: {pqcb.backend_available('ML-KEM-768')}")
print(f"ML-DSA-65 available: {pqcb.backend_available('ML-DSA-65')}")

kem_public_key, kem_secret_key = pqcb.kem_keypair()
ciphertext, encapsulated = pqcb.kem_encapsulate(kem_public_key)
decapsulated = pqcb.kem_decapsulate(kem_secret_key, ciphertext)

if encapsulated != decapsulated:
    raise RuntimeError("ML-KEM shared secrets did not match")

signature_public_key, signature_secret_key = pqcb.signature_keypair()
message = b"pqcb python example"
signature = pqcb.sign(signature_secret_key, message)
pqcb.verify(signature_public_key, message, signature)

print("Python primitive example completed")
