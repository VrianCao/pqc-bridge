import { kem, signature, VerificationFailedError } from "./index.js";

const kemKeypair = kem.keypair();
const encapsulation = kem.encapsulate(kemKeypair.publicKey);
const decapsulated = kem.decapsulate(
  kemKeypair.secretKey,
  encapsulation.ciphertext,
);

if (!encapsulation.sharedSecret.equals(decapsulated)) {
  throw new Error("ML-KEM shared secrets did not match");
}

const signatureKeypair = signature.keypair();
const message = Buffer.from("pqcb node primitive smoke", "utf8");
const signatureBytes = signature.sign(signatureKeypair.secretKey, message);

signature.verify(signatureKeypair.publicKey, message, signatureBytes);

try {
  signature.verify(
    signatureKeypair.publicKey,
    Buffer.from("tampered", "utf8"),
    signatureBytes,
  );
  throw new Error("tampered ML-DSA signature unexpectedly verified");
} catch (error) {
  if (!(error instanceof VerificationFailedError)) {
    throw error;
  }
}

console.log(
  JSON.stringify({
    kemSharedSecretLength: encapsulation.sharedSecret.length,
    signatureLength: signatureBytes.length,
    tamperedSignatureRejected: true,
  }),
);
