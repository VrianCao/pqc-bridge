import { kem, signature, VerificationFailedError } from "./index.js";

console.error("node primitive smoke: kem keypair");
const kemKeypair = kem.keypair();
console.error("node primitive smoke: kem encapsulate");
const encapsulation = kem.encapsulate(kemKeypair.publicKey);
console.error("node primitive smoke: kem decapsulate");
const decapsulated = kem.decapsulate(
  kemKeypair.secretKey,
  encapsulation.ciphertext,
);

if (!encapsulation.sharedSecret.equals(decapsulated)) {
  throw new Error("ML-KEM shared secrets did not match");
}

console.error("node primitive smoke: signature keypair");
const signatureKeypair = signature.keypair();
const message = Buffer.from("pqcb node primitive smoke", "utf8");
console.error("node primitive smoke: signature sign");
const signatureBytes = signature.sign(signatureKeypair.secretKey, message);

console.error("node primitive smoke: signature verify");
signature.verify(signatureKeypair.publicKey, message, signatureBytes);

try {
  console.error("node primitive smoke: signature tamper check");
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
