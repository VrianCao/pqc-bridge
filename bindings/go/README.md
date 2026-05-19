# pqcb-go

Go bindings for PQC Bridge.

This module links the local PQC Bridge C ABI dynamic library for development
smoke tests. Build the native library from the repository root first:

```sh
cargo build -p pqcb-ffi
go test ./...
go run ./examples/primitives
```

The cgo linker flags point at `../../target/debug` from this module.
