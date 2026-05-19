# @pqcbridge/pqcb

Node.js bindings for PQC Bridge.

This package loads the local PQC Bridge C ABI dynamic library for development
smoke tests. Build the native library from the repository root first:

```sh
cargo build -p pqcb-ffi
npm run smoke:abi
npm run smoke:primitives
npm run pack:dry-run
```

Set `PQCB_FFI_LIBRARY_PATH` to load a specific `pqcb-ffi` dynamic library.

After `npm run build`, run `node examples/primitives.mjs` for a minimal
ML-KEM-768 and ML-DSA-65 workflow.
