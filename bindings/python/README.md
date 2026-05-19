# pqcb

Python bindings for PQC Bridge.

This package loads the local PQC Bridge C ABI dynamic library for development
smoke tests. Build the native library from the repository root first:

```sh
cargo build -p pqcb-ffi
python smoke_abi.py
python smoke_primitives.py
python -m compileall pqcb
python -m build --wheel --outdir dist
```

Set `PQCB_FFI_LIBRARY_PATH` to load a specific `pqcb-ffi` dynamic library.

Run `python examples/primitives.py` for a minimal ML-KEM-768 and ML-DSA-65
workflow.
