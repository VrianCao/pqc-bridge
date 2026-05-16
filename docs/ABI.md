# C ABI Policy

The C ABI is the stable boundary for most language bindings.

## v0.1 ABI

The v0.1 ABI exposes:

- ABI version
- package version

Cryptographic functions are intentionally not exposed until backend integration,
memory ownership rules, and tests are ready.

## Future ABI Rules

The ABI should define:

- ownership of input buffers
- ownership of output buffers
- allocator and deallocator rules
- error codes
- version negotiation
- thread-safety expectations
- feature detection

## Naming

All exported C symbols use the `pqcb_` prefix.

## Compatibility

Before v1.0, ABI changes are allowed with changelog notes.

At v1.0, ABI major version changes should be reserved for breaking changes.
