import { abiMajorVersion, backendAvailable, version } from "./index.js";

const abiMajor = abiMajorVersion();
const abiVersion = version();
const kemAvailable = backendAvailable("ML-KEM-768");
const signatureAvailable = backendAvailable("ML-DSA-65");

console.log(
  JSON.stringify({
    abiMajor,
    abiVersion,
    kemAvailable,
    signatureAvailable,
  }),
);
