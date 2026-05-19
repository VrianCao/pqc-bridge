import { backendAvailable, version } from "./index.js";

const abiVersion = version();
const kemAvailable = backendAvailable("ML-KEM-768");
const signatureAvailable = backendAvailable("ML-DSA-65");

console.log(
  JSON.stringify({
    abiVersion,
    kemAvailable,
    signatureAvailable,
  }),
);
