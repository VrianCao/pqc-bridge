import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type * as Koffi from "koffi";

const require = createRequire(import.meta.url);
const koffi = require("koffi") as typeof Koffi;

export const name = "PQC Bridge";
export const packageName = "pqcb";
export const packageVersion = "0.1.0";

export type KemAlgorithm = "ML-KEM-768";
export type SignatureAlgorithm = "ML-DSA-65";
export type HybridKemAlgorithm = "X25519-ML-KEM-768";

const ALGORITHMS = {
  "ML-KEM-768": 1,
  "ML-DSA-65": 2,
} as const;

type PrimitiveAlgorithm = keyof typeof ALGORITHMS;

const STATUS = {
  Ok: 0,
  NullPointer: 1,
  InvalidLength: 2,
  InvalidAlgorithm: 3,
  BackendUnavailable: 4,
  VerificationFailed: 5,
  CryptoFailure: 6,
  Panic: 255,
} as const;

export class PqcbError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PqcbError";
  }
}

export class NullPointerError extends PqcbError {
  constructor(operation: string) {
    super(`${operation} returned a null pointer error`);
    this.name = "NullPointerError";
  }
}

export class InvalidLengthError extends PqcbError {
  constructor(operation: string) {
    super(`${operation} received an invalid buffer length`);
    this.name = "InvalidLengthError";
  }
}

export class InvalidAlgorithmError extends PqcbError {
  constructor(algorithm: string) {
    super(`unsupported or unknown algorithm: ${algorithm}`);
    this.name = "InvalidAlgorithmError";
  }
}

export class BackendUnavailableError extends PqcbError {
  constructor(operation: string, cause?: unknown) {
    super(`${operation} backend is unavailable`);
    this.name = "BackendUnavailableError";
    this.cause = cause;
  }
}

export class VerificationFailedError extends PqcbError {
  constructor() {
    super("signature verification failed");
    this.name = "VerificationFailedError";
  }
}

export class CryptoFailureError extends PqcbError {
  constructor(operation: string) {
    super(`${operation} cryptographic operation failed`);
    this.name = "CryptoFailureError";
  }
}

export class PanicError extends PqcbError {
  constructor(operation: string) {
    super(`${operation} panic caught at FFI boundary`);
    this.name = "PanicError";
  }
}

type NativeLibrary = {
  pqcb_version: () => { major: number; minor: number; patch: number };
  pqcb_backend_available: (algorithmId: number, available: [boolean]) => number;
};

let loadedNative: NativeLibrary | undefined;

export function nativeLibraryPath(): string {
  if (process.env.PQCB_FFI_LIBRARY_PATH) {
    return process.env.PQCB_FFI_LIBRARY_PATH;
  }

  const currentDir = dirname(fileURLToPath(import.meta.url));
  const libraryName =
    process.platform === "win32"
      ? "pqcb_ffi.dll"
      : process.platform === "darwin"
        ? "libpqcb_ffi.dylib"
        : "libpqcb_ffi.so";

  return resolve(currentDir, "..", "..", "..", "target", "debug", libraryName);
}

function native(): NativeLibrary {
  if (loadedNative) {
    return loadedNative;
  }

  const libraryPath = nativeLibraryPath();
  if (!existsSync(libraryPath)) {
    throw new BackendUnavailableError("native library load", libraryPath);
  }

  try {
    const library = koffi.load(libraryPath);
    const pqcbVersion = koffi.struct("PqcbVersion", {
      major: "uint16_t",
      minor: "uint16_t",
      patch: "uint16_t",
    });

    loadedNative = {
      pqcb_version: library.func("pqcb_version", pqcbVersion, []) as NativeLibrary["pqcb_version"],
      pqcb_backend_available: library.func("pqcb_backend_available", "uint32_t", [
        "uint32_t",
        koffi.out(koffi.pointer("bool")),
      ]) as NativeLibrary["pqcb_backend_available"],
    };
    return loadedNative;
  } catch (error) {
    throw new BackendUnavailableError("native library load", error);
  }
}

export function version(): string {
  const abiVersion = native().pqcb_version();
  return `${abiVersion.major}.${abiVersion.minor}.${abiVersion.patch}`;
}

export function backendAvailable(algorithm: PrimitiveAlgorithm): boolean {
  const algorithmId = ALGORITHMS[algorithm];
  if (algorithmId === undefined) {
    throw new InvalidAlgorithmError(algorithm);
  }

  const available: [boolean] = [false];
  const status = native().pqcb_backend_available(algorithmId, available);
  throwIfError(status, "backend availability", algorithm);
  return available[0];
}

function throwIfError(status: number, operation: string, algorithm?: string): void {
  switch (status) {
    case STATUS.Ok:
      return;
    case STATUS.NullPointer:
      throw new NullPointerError(operation);
    case STATUS.InvalidLength:
      throw new InvalidLengthError(operation);
    case STATUS.InvalidAlgorithm:
      throw new InvalidAlgorithmError(algorithm ?? "unknown");
    case STATUS.BackendUnavailable:
      throw new BackendUnavailableError(operation);
    case STATUS.VerificationFailed:
      throw new VerificationFailedError();
    case STATUS.CryptoFailure:
      throw new CryptoFailureError(operation);
    case STATUS.Panic:
      throw new PanicError(operation);
    default:
      throw new CryptoFailureError(operation);
  }
}

export async function createSecureSession(): Promise<never> {
  throw new BackendUnavailableError("SecureSession");
}
