# Release Checklist

## Every Release

- [ ] Update `CHANGELOG.md`.
- [ ] Confirm version numbers.
- [ ] Run `./scripts/check.sh`.
- [ ] Run binding smoke tests.
- [ ] Confirm release workflow gates pass.
- [ ] Confirm release tag policy gate passes for tag releases.
- [ ] Confirm security disclaimers are accurate.
- [ ] Confirm dependency audit status.
- [ ] Confirm fuzz target build checks pass.
- [ ] Confirm `RELEASE_GPG_PUBLIC_KEYS` contains the authorized release signing
  public key before creating a production tag.
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
- Dependency audit and license/policy review through `cargo-audit` and
  `cargo-deny`.
- Fuzz target build checks for `envelope_decode` and `ffi_primitives`.
- Node.js, Python, and Go binding smoke tests against the C ABI.
- Java, Swift, and C/C++ binding build checks.
- SemVer tag format and signed annotated tag verification for tag-triggered
  releases. The verifier imports authorized maintainer public keys from the
  `RELEASE_GPG_PUBLIC_KEYS` repository variable.
- Rust crate packaging, Node.js `npm pack --dry-run`, and Python sdist/wheel
  build checks where package metadata exists.
- Source archive generation, SHA-256 checksum generation, and SPDX SBOM
  generation.
- Sigstore-backed provenance and SBOM attestations for source release
  materials.
- GitHub Release asset upload for signed tag releases.

Release workflow permissions must stay minimal. Jobs default to `contents: read`.
Only the attestation job requests `id-token: write` and `attestations: write`,
which are required for artifact attestations. The SBOM/source-material job stays
read-only. Only the tag-only release asset publication job requests
`contents: write`. Release jobs must not request package, issue, or pull request
write permissions.

## Release Integrity Verification

Before publishing release notes, record the results of:

```sh
git tag -v vX.Y.Z
shasum -a 256 -c SHA256SUMS
SOURCE_DIGEST="$(git rev-parse vX.Y.Z^{})"
gh attestation verify pqc-bridge-source.tar.gz \
  -R VrianCao/pqc-bridge \
  --signer-workflow VrianCao/pqc-bridge/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z \
  --source-digest "${SOURCE_DIGEST}"
gh attestation verify pqc-bridge-source.tar.gz \
  -R VrianCao/pqc-bridge \
  --signer-workflow VrianCao/pqc-bridge/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z \
  --source-digest "${SOURCE_DIGEST}" \
  --predicate-type https://spdx.dev/Document/v2.3
```

If any verification step is not applicable, release notes must say why. A stable
release must not proceed with an unsigned tag, missing checksum file, missing
SBOM, or missing provenance attestation.

## v1.0 Readiness Dry Run - 2026-05-19

Dry run target:

- Branch: `v1-stable-release-hardening`
- Commit: `e7eaef2a5c7b63ef8010ffb948919b71b4a4f712`
- Release workflow run:
  `https://github.com/VrianCao/pqc-bridge/actions/runs/26114308177`

Checklist execution:

| Item | Result | Evidence |
| --- | --- | --- |
| Update `CHANGELOG.md` | Pass | Release-notes draft records the v1.0 readiness dry-run verification. |
| Confirm version numbers | Pass | Workspace remains pre-v1.0; no production tag or registry publish was attempted. |
| Run `./scripts/check.sh` | Pass | Local run completed successfully on 2026-05-19. |
| Run binding smoke tests | Pass | Release workflow run `26114308177` passed Node.js, Python, and Go binding smoke tests. |
| Confirm release workflow gates pass | Pass | Release workflow run `26114308177` completed successfully. |
| Confirm release tag policy gate passes for tag releases | Not applicable | Dry run used `workflow_dispatch`; tag policy is enforced for `refs/tags/vX.Y.Z` releases. |
| Confirm security disclaimers are accurate | Pass | `README.md`, `SECURITY.md`, `docs/THREAT_MODEL.md`, and `docs/security/FIPS.md` distinguish standards compatibility, review status, side-channel scope, and FIPS certification status. |
| Confirm dependency audit status | Pass | PR dependency review, `cargo-deny`, and `cargo-audit` checks passed on this branch; release workflow now includes dependency audit gates. |
| Confirm fuzz target build checks pass | Pass | `cargo +nightly fuzz build envelope_decode`, `cargo +nightly fuzz build ffi_primitives`, and bounded `-runs=256` fuzz smoke runs passed during v1.0 hardening; release workflow now type-checks both fuzz targets. |
| Confirm `RELEASE_GPG_PUBLIC_KEYS` contains the authorized release signing public key before creating a production tag | Not applicable | Dry run did not create a tag; production tag releases require the repository variable or another trusted runner keyring source before `git tag -v` can pass. |
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
| Add parser fuzzing | Pass | Fuzz targets, seed corpora, build checks, and bounded smoke commands are documented in `docs/QUALITY.md`; release workflow checks both fuzz targets. |
| Add release signing | Pass with dry-run limitation | Signed tags are required by policy; the dry run did not create a tag. |
| Generate SBOM | Pass | Release workflow generated `sbom.spdx.json`. |
| Generate checksums | Pass | Release workflow generated `SHA256SUMS`. |
| Generate provenance attestations | Pass | Release workflow generated GitHub artifact attestations. |
| Document backend provenance | Pass | `docs/BACKENDS.md` and `docs/rfcs/0002-backend-selection.md` document the selected backend and provenance requirements. |
| Complete external security review plan | Pass | `docs/security/AUDIT_PLAN.md`, `docs/THREAT_MODEL.md`, and `docs/security/FIPS.md` document reporting, audit readiness scope, claim boundaries, evidence package, exit criteria, and open risks. |

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
