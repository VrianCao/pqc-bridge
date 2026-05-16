# Release Checklist

## Every Release

- [ ] Update `CHANGELOG.md`.
- [ ] Confirm version numbers.
- [ ] Run `./scripts/check.sh`.
- [ ] Run binding smoke tests.
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
