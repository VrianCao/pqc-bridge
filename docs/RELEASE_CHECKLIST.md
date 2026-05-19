# Release Checklist

## Every Release

- [ ] Update `CHANGELOG.md`.
- [ ] Confirm version numbers.
- [ ] Run `./scripts/check.sh`.
- [ ] Run binding smoke tests.
- [ ] Confirm release workflow gates pass.
- [ ] Confirm security disclaimers are accurate.
- [ ] Confirm dependency audit status.
- [ ] Tag release.
- [ ] Publish release notes.

## Before First Stable Release

- [ ] Define API compatibility policy.
- [ ] Define C ABI compatibility policy.
- [ ] Add production backend KAT coverage.
- [ ] Add parser fuzzing.
- [ ] Add release signing.
- [ ] Generate SBOM.
- [ ] Generate checksums.
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

Release workflow permissions must stay minimal. Jobs default to `contents: read`
and do not request package, issue, pull request, or token write permissions.

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
