import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type * as Koffi from "koffi";

const require = createRequire(import.meta.url);
const koffi = require("koffi") as typeof Koffi;

export const name = "PQC Bridge";
export const packageName = "pqcb";
export const packageVersion = "0.2.0";

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

const SUPPORTED_ABI_MAJOR = 1;

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

export class UnsupportedAbiError extends PqcbError {
  constructor(actual: number | string) {
    super(`unsupported PQC Bridge C ABI major version: ${actual}`);
    this.name = "UnsupportedAbiError";
  }
}

type NativeLibrary = {
  pqcb_abi_version_major: () => number;
  pqcb_version: () => { major: number; minor: number; patch: number };
  pqcb_backend_available: (algorithmId: number, available: [boolean]) => number;
  pqcb_ml_kem_768_keypair: (
    publicKey: [OwnedBuffer],
    secretKey: [OwnedBuffer],
  ) => number;
  pqcb_ml_kem_768_encapsulate: (
    publicKey: BorrowedBuffer,
    ciphertext: [OwnedBuffer],
    sharedSecret: [OwnedBuffer],
  ) => number;
  pqcb_ml_kem_768_decapsulate: (
    secretKey: BorrowedBuffer,
    ciphertext: BorrowedBuffer,
    sharedSecret: [OwnedBuffer],
  ) => number;
  pqcb_ml_dsa_65_keypair: (
    publicKey: [OwnedBuffer],
    secretKey: [OwnedBuffer],
  ) => number;
  pqcb_ml_dsa_65_sign: (
    secretKey: BorrowedBuffer,
    message: BorrowedBuffer,
    signature: [OwnedBuffer],
  ) => number;
  pqcb_ml_dsa_65_verify: (
    publicKey: BorrowedBuffer,
    message: BorrowedBuffer,
    signature: BorrowedBuffer,
  ) => number;
  pqcb_buffer_free_parts: (data: bigint, len: number) => void;
};

type BorrowedBuffer = {
  data: Buffer;
  len: number;
};

type OwnedBuffer = {
  data?: bigint | null;
  len?: number;
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
    const borrowedBuffer = koffi.struct("PqcbBuffer", {
      data: "void *",
      len: "size_t",
    });
    const ownedBuffer = koffi.struct("PqcbOwnedBuffer", {
      data: "void *",
      len: "size_t",
    });
    const ownedBufferOut = () => koffi.out(koffi.pointer(ownedBuffer));
    let abiVersionMajor: NativeLibrary["pqcb_abi_version_major"];
    try {
      abiVersionMajor = library.func(
        "pqcb_abi_version_major",
        "uint16_t",
        [],
      ) as NativeLibrary["pqcb_abi_version_major"];
    } catch {
      throw new UnsupportedAbiError("missing pqcb_abi_version_major");
    }

    loadedNative = {
      pqcb_abi_version_major: abiVersionMajor,
      pqcb_version: library.func("pqcb_version", pqcbVersion, []) as NativeLibrary["pqcb_version"],
      pqcb_backend_available: library.func("pqcb_backend_available", "uint32_t", [
        "uint32_t",
        koffi.out(koffi.pointer("bool")),
      ]) as NativeLibrary["pqcb_backend_available"],
      pqcb_ml_kem_768_keypair: library.func("pqcb_ml_kem_768_keypair", "uint32_t", [
        ownedBufferOut(),
        ownedBufferOut(),
      ]) as NativeLibrary["pqcb_ml_kem_768_keypair"],
      pqcb_ml_kem_768_encapsulate: library.func("pqcb_ml_kem_768_encapsulate", "uint32_t", [
        borrowedBuffer,
        ownedBufferOut(),
        ownedBufferOut(),
      ]) as NativeLibrary["pqcb_ml_kem_768_encapsulate"],
      pqcb_ml_kem_768_decapsulate: library.func("pqcb_ml_kem_768_decapsulate", "uint32_t", [
        borrowedBuffer,
        borrowedBuffer,
        ownedBufferOut(),
      ]) as NativeLibrary["pqcb_ml_kem_768_decapsulate"],
      pqcb_ml_dsa_65_keypair: library.func("pqcb_ml_dsa_65_keypair", "uint32_t", [
        ownedBufferOut(),
        ownedBufferOut(),
      ]) as NativeLibrary["pqcb_ml_dsa_65_keypair"],
      pqcb_ml_dsa_65_sign: library.func("pqcb_ml_dsa_65_sign", "uint32_t", [
        borrowedBuffer,
        borrowedBuffer,
        ownedBufferOut(),
      ]) as NativeLibrary["pqcb_ml_dsa_65_sign"],
      pqcb_ml_dsa_65_verify: library.func("pqcb_ml_dsa_65_verify", "uint32_t", [
        borrowedBuffer,
        borrowedBuffer,
        borrowedBuffer,
      ]) as NativeLibrary["pqcb_ml_dsa_65_verify"],
      pqcb_buffer_free_parts: library.func("pqcb_buffer_free_parts", "void", [
        "void *",
        "size_t",
      ]) as NativeLibrary["pqcb_buffer_free_parts"],
    };
    const abiMajor = loadedNative.pqcb_abi_version_major();
    if (abiMajor !== SUPPORTED_ABI_MAJOR) {
      loadedNative = undefined;
      throw new UnsupportedAbiError(abiMajor);
    }
    return loadedNative;
  } catch (error) {
    if (error instanceof UnsupportedAbiError) {
      throw error;
    }
    throw new BackendUnavailableError("native library load", error);
  }
}

export function abiMajorVersion(): number {
  return native().pqcb_abi_version_major();
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

export type KemKeypair = {
  publicKey: Buffer;
  secretKey: Buffer;
};

export type Encapsulation = {
  ciphertext: Buffer;
  sharedSecret: Buffer;
};

export type SignatureKeypair = {
  publicKey: Buffer;
  secretKey: Buffer;
};

export const kem = {
  keypair(): KemKeypair {
    const publicKey: [OwnedBuffer] = [{}];
    const secretKey: [OwnedBuffer] = [{}];
    const status = native().pqcb_ml_kem_768_keypair(publicKey, secretKey);
    throwIfError(status, "ML-KEM-768 keypair", "ML-KEM-768");

    return {
      publicKey: takeOwnedBuffer(publicKey[0], "ML-KEM-768 public key"),
      secretKey: takeOwnedBuffer(secretKey[0], "ML-KEM-768 secret key"),
    };
  },

  encapsulate(publicKey: Buffer): Encapsulation {
    const ciphertext: [OwnedBuffer] = [{}];
    const sharedSecret: [OwnedBuffer] = [{}];
    const status = native().pqcb_ml_kem_768_encapsulate(
      borrow(publicKey),
      ciphertext,
      sharedSecret,
    );
    throwIfError(status, "ML-KEM-768 encapsulate", "ML-KEM-768");

    return {
      ciphertext: takeOwnedBuffer(ciphertext[0], "ML-KEM-768 ciphertext"),
      sharedSecret: takeOwnedBuffer(sharedSecret[0], "ML-KEM-768 shared secret"),
    };
  },

  decapsulate(secretKey: Buffer, ciphertext: Buffer): Buffer {
    const sharedSecret: [OwnedBuffer] = [{}];
    const status = native().pqcb_ml_kem_768_decapsulate(
      borrow(secretKey),
      borrow(ciphertext),
      sharedSecret,
    );
    throwIfError(status, "ML-KEM-768 decapsulate", "ML-KEM-768");
    return takeOwnedBuffer(sharedSecret[0], "ML-KEM-768 shared secret");
  },
};

export const signature = {
  keypair(): SignatureKeypair {
    const publicKey: [OwnedBuffer] = [{}];
    const secretKey: [OwnedBuffer] = [{}];
    const status = native().pqcb_ml_dsa_65_keypair(publicKey, secretKey);
    throwIfError(status, "ML-DSA-65 keypair", "ML-DSA-65");

    return {
      publicKey: takeOwnedBuffer(publicKey[0], "ML-DSA-65 public key"),
      secretKey: takeOwnedBuffer(secretKey[0], "ML-DSA-65 secret key"),
    };
  },

  sign(secretKey: Buffer, message: Buffer): Buffer {
    const signatureBytes: [OwnedBuffer] = [{}];
    const status = native().pqcb_ml_dsa_65_sign(
      borrow(secretKey),
      borrow(message),
      signatureBytes,
    );
    throwIfError(status, "ML-DSA-65 sign", "ML-DSA-65");
    return takeOwnedBuffer(signatureBytes[0], "ML-DSA-65 signature");
  },

  verify(publicKey: Buffer, message: Buffer, signatureBytes: Buffer): true {
    const status = native().pqcb_ml_dsa_65_verify(
      borrow(publicKey),
      borrow(message),
      borrow(signatureBytes),
    );
    throwIfError(status, "ML-DSA-65 verify", "ML-DSA-65");
    return true;
  },
};

function borrow(buffer: Buffer): BorrowedBuffer {
  return {
    data: buffer,
    len: buffer.length,
  };
}

function takeOwnedBuffer(buffer: OwnedBuffer, field: string): Buffer {
  if (!buffer.data || !buffer.len) {
    throw new NullPointerError(field);
  }

  try {
    return Buffer.from(koffi.decode(buffer.data, "uint8_t", buffer.len));
  } finally {
    native().pqcb_buffer_free_parts(buffer.data, buffer.len);
  }
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
