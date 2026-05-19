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

Package and smoke checks:

- Node.js: `npm run check`, `npm run smoke:abi`, `npm run smoke:primitives`,
  and `npm run pack:dry-run` from `bindings/node`
- Python: `python -m compileall pqcb`, `python smoke_abi.py`,
  `python smoke_primitives.py`, and `python -m build --wheel --outdir dist`
  from `bindings/python`
- Go: `go test ./...` and `go run ./examples/primitives` from `bindings/go`

Planned high-level examples:

- `secure-session-node`
- `secure-session-python`
- `secure-session-go`
- `signed-message`
- `sealed-box`
- `file-envelope`
- `ffi-c`

Examples must not use mock cryptography.
