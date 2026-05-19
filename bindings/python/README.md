# pqcb

Python bindings for PQC Bridge.

This package loads the local PQC Bridge C ABI dynamic library for development
smoke tests. Build the native library from the repository root first:

```sh
cargo build -p pqcb-ffi
python smoke_abi.py
```

Set `PQCB_FFI_LIBRARY_PATH` to load a specific `pqcb-ffi` dynamic library.
