# @pqcbridge/pqcb

Node.js bindings for PQC Bridge.

This package loads the local PQC Bridge C ABI dynamic library for development
smoke tests. Build the native library from the repository root first:

```sh
cargo build -p pqcb-ffi
npm run smoke:abi
```

Set `PQCB_FFI_LIBRARY_PATH` to load a specific `pqcb-ffi` dynamic library.
