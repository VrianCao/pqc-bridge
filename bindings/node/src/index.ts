export const name = "PQC Bridge";
export const packageName = "pqcb";
export const version = "0.1.0";

export type KemAlgorithm = "ML-KEM-768";
export type SignatureAlgorithm = "ML-DSA-65";
export type HybridKemAlgorithm = "X25519-ML-KEM-768";

export class BackendUnavailableError extends Error {
  constructor(operation: string) {
    super(`${operation} backend is not configured in the v0.1 scaffold`);
    this.name = "BackendUnavailableError";
  }
}

export async function createSecureSession(): Promise<never> {
  throw new BackendUnavailableError("SecureSession");
}
