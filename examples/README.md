# Examples

The first binding examples exercise the reviewed RustCrypto-backed primitive
path through the C ABI:

- Node.js: `bindings/node/examples/primitives.mjs`
- Python: `bindings/python/examples/primitives.py`
- Go: `bindings/go/examples/primitives`

Build the C ABI dynamic library before running binding examples:

```sh
cargo build -p pqcb-ffi
```

High-level Rust examples:

```sh
cargo run -p pqcb-backend-rustcrypto --example signed_message
cargo run -p pqcb-backend-rustcrypto --example sealed_box
cargo run -p pqcb-backend-rustcrypto --example hybrid_session
cargo run -p pqcb-core --example secure_session
```

`secure_session` demonstrates the v0.4 state-machine skeleton. The
`hybrid_session` example demonstrates the v0.5 X25519 + ML-KEM-768 combiner
through the RustCrypto-backed facade.

Package and smoke checks:

- Node.js: `npm run check`, `npm run smoke:abi`, `npm run smoke:primitives`,
  and `npm run pack:dry-run` from `bindings/node`
- Python: `python -m compileall pqcb`, `python smoke_abi.py`,
  `python smoke_primitives.py`, and `python -m build --wheel --outdir dist`
  from `bindings/python`
- Go: `go test ./...` and `go run ./examples/primitives` from `bindings/go`

Planned future examples:

- file-envelope
- ffi-c

Examples must not use mock cryptography.
