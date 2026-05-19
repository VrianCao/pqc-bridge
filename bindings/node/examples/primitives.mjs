import { backendAvailable, kem, signature, version } from "../dist/index.js";

console.log(`PQC Bridge ${version()}`);
console.log(`ML-KEM-768 available: ${backendAvailable("ML-KEM-768")}`);
console.log(`ML-DSA-65 available: ${backendAvailable("ML-DSA-65")}`);

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
const message = Buffer.from("pqcb node example", "utf8");
const signatureBytes = signature.sign(signatureKeypair.secretKey, message);
signature.verify(signatureKeypair.publicKey, message, signatureBytes);

console.log("Node primitive example completed");
