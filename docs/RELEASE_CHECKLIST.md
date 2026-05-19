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

## v1.0 Readiness Dry Run - 2026-05-19

Dry run target:

- Branch: `v1-stable-release-hardening`
- Commit: `bbe46a63e8f5e4922ab87ff660cd34f829df63b8`
- Release workflow run:
  `https://github.com/VrianCao/pqc-bridge/actions/runs/26114163526`

Checklist execution:

| Item | Result | Evidence |
| --- | --- | --- |
| Update `CHANGELOG.md` | Pass | Release-notes draft records the v1.0 readiness dry-run verification. |
| Confirm version numbers | Pass | Workspace remains pre-v1.0; no production tag or registry publish was attempted. |
| Run `./scripts/check.sh` | Pass | Local run completed successfully on 2026-05-19. |
| Run binding smoke tests | Pass | Release workflow run `26114163526` passed Node.js, Python, and Go binding smoke tests. |
| Confirm release workflow gates pass | Pass | Release workflow run `26114163526` completed successfully. |
| Confirm security disclaimers are accurate | Pass | `README.md`, `SECURITY.md`, `docs/THREAT_MODEL.md`, and `docs/security/FIPS.md` distinguish standards compatibility, review status, side-channel scope, and FIPS certification status. |
| Confirm dependency audit status | Pass | PR dependency review, `cargo-deny`, and `cargo-audit` checks passed on this branch before the dry run. |
| Create and verify signed release tag | Not applicable | Dry run intentionally did not create or publish a production tag. Stable tagging remains blocked unless a signed `vX.Y.Z` tag is created and verified with `git tag -v`. |
| Confirm release checksums | Pass | Release workflow generated `SHA256SUMS` for `pqc-bridge-source.tar.gz` and `sbom.spdx.json`. |
| Confirm release artifact attestations | Pass | Release workflow generated provenance and SBOM attestations for the source release material. |
| Publish release notes | Not applicable | Dry run produced a release-notes draft only; no GitHub release or registry package was published. |

First-stable prerequisites:

| Item | Result | Evidence |
| --- | --- | --- |
| Define API compatibility policy | Pass | `docs/RELEASE.md` defines SemVer, compatibility surface, and deprecation behavior. |
| Define C ABI compatibility policy | Pass | `docs/ABI.md` defines ABI versioning and breaking-change behavior. |
| Add production backend KAT coverage | Pass | Release workflow Rust job runs KAT tests for ML-KEM-768, ML-DSA-65, and hybrid vectors. |
| Add parser fuzzing | Pass | Fuzz targets and seed corpora are documented in `docs/QUALITY.md`. |
| Add release signing | Pass with dry-run limitation | Signed tags are required by policy; the dry run did not create a tag. |
| Generate SBOM | Pass | Release workflow generated `sbom.spdx.json`. |
| Generate checksums | Pass | Release workflow generated `SHA256SUMS`. |
| Generate provenance attestations | Pass | Release workflow generated GitHub artifact attestations. |
| Document backend provenance | Pass | `docs/BACKENDS.md` and `docs/rfcs/0002-backend-selection.md` document the selected backend and provenance requirements. |
| Complete external security review plan | Pass | `docs/THREAT_MODEL.md` and `docs/security/FIPS.md` document audit readiness scope, claim boundaries, and open risks. |

Open blocker review:

- No unresolved P0 Project items remain in the `v1.0 Stable` phase after this
  dry run.
- Later-phase backend, SLH-DSA, migration scanner, and KMS adapter work remains
  tracked outside the v1.0 stable-release hardening scope.
- The GitHub Actions Node.js 20 deprecation annotation is a future maintenance
  warning for third-party actions. It did not fail the dry run and is not a
  stable-release blocker.

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
