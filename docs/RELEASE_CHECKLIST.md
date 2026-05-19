# Release Checklist

## Every Release

- [ ] Update `CHANGELOG.md`.
- [ ] Confirm version numbers.
- [ ] Run `./scripts/check.sh`.
- [ ] Run binding smoke tests.
- [ ] Confirm release workflow gates pass.
- [ ] Confirm security disclaimers are accurate.
- [ ] Confirm dependency audit status.
- [ ] Create and verify signed release tag.
- [ ] Confirm release checksums.
- [ ] Confirm release artifact attestations.
- [ ] Publish release notes.

## Before First Stable Release

- [ ] Define API compatibility policy.
- [ ] Define C ABI compatibility policy.
- [ ] Add production backend KAT coverage.
- [ ] Add parser fuzzing.
- [ ] Add release signing.
- [ ] Generate SBOM.
- [ ] Generate checksums.
- [ ] Generate provenance attestations.
- [ ] Document backend provenance.
- [ ] Complete external security review plan.

## Release Workflow Gates

The release workflow is runnable from `workflow_dispatch` for dry runs and from
version tags for release candidates. Release artifacts are uploaded only after
all gates below pass:

- Rust formatting, workspace check, all-target tests, KAT harnesses, and clippy.
- Node.js, Python, and Go binding smoke tests against the C ABI.
- Java, Swift, and C/C++ binding build checks.
- Rust crate packaging, Node.js `npm pack --dry-run`, and Python sdist/wheel
  build checks where package metadata exists.
- Source archive generation, SHA-256 checksum generation, and SPDX SBOM
  generation.
- Sigstore-backed provenance and SBOM attestations for source release
  materials.

Release workflow permissions must stay minimal. Jobs default to `contents: read`.
Only the release material job requests `id-token: write` and
`attestations: write`, which are required for artifact attestations. It must not
request package, issue, pull request, or repository content write permissions.

## Release Integrity Verification

Before publishing release notes, record the results of:

```sh
git tag -v vX.Y.Z
shasum -a 256 -c SHA256SUMS
gh attestation verify pqc-bridge-source.tar.gz -R VrianCao/pqc-bridge
gh attestation verify pqc-bridge-source.tar.gz \
  -R VrianCao/pqc-bridge \
  --predicate-type https://spdx.dev/Document/v2.3
```

If any verification step is not applicable, release notes must say why. A stable
release must not proceed with an unsigned tag, missing checksum file, missing
SBOM, or missing provenance attestation.

## Release Notes Template

```text
## Summary

## Added

## Changed

## Fixed

## Security

## Compatibility

## Verification
```
