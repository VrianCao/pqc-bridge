# Known-Answer Tests

This directory stores known-answer test manifests and fixtures.

All production backend integrations must include KAT coverage before release.

## Layout

```text
tests/kat/
  manifest-rules.jq
  sample-manifest.json
  ml-kem-768/
    manifest.json
    vectors/
  ml-dsa-65/
    manifest.json
    vectors/
  slh-dsa/
  hybrid/
```

Each algorithm directory owns one `manifest.json`. Large binary fixtures should
live under `vectors/` and be referenced by relative path from the manifest.

## Manifest Format

KAT manifests are JSON objects. The current schema version is `1`.

Required top-level fields:

| Field | Type | Requirement |
| --- | --- | --- |
| `schema_version` | string | Must be `"1"`. |
| `algorithm` | string | Canonical algorithm family, for example `"ML-KEM"` or `"ML-DSA"`. |
| `parameter_set` | string | Canonical parameter set, for example `"ML-KEM-768"` or `"ML-DSA-65"`. |
| `upstream` | object | Upstream repository, package, and version metadata. |
| `source` | object | Vector source, URL or path, license, and redistribution terms. |
| `generation` | object | Reproducible generation method and toolchain notes. |
| `checksum` | object | Digest algorithm and hex digest covering the manifest payload or fixture bundle. |
| `cases` | array | Positive and negative test cases. |

Required `upstream` fields:

| Field | Type | Requirement |
| --- | --- | --- |
| `name` | string | Provider or vector source name. |
| `repository` | string | Reviewable repository URL. |
| `version` | string | Exact crate version, release, or commit. |

Required `source` fields:

| Field | Type | Requirement |
| --- | --- | --- |
| `name` | string | Human-readable source name. |
| `url` | string | Reviewable URL or relative path. |
| `license` | string | SPDX identifier or redistribution terms. |
| `redistribution` | string | Short redistribution note. |

Required `generation` fields:

| Field | Type | Requirement |
| --- | --- | --- |
| `method` | string | `upstream`, `nist-acvp`, `wycheproof`, `project-generated`, or `manual-negative`. |
| `command` | string | Exact command, script, or `not-applicable`. |
| `date` | string | ISO-8601 date. |

Required `checksum` fields:

| Field | Type | Requirement |
| --- | --- | --- |
| `algorithm` | string | Digest algorithm, initially `SHA-256`. |
| `value` | string | Lowercase hex digest. |

Required case fields:

| Field | Type | Requirement |
| --- | --- | --- |
| `id` | string | Stable case identifier unique within the manifest. |
| `type` | string | `positive` or `negative`. |
| `operation` | string | Algorithm-specific operation such as `keygen`, `encapsulate`, `decapsulate`, `sign`, or `verify`. |
| `expected` | string | `success`, `invalid-length`, `verification-failed`, `crypto-failure`, or `changed-secret`. |
| `inputs` | object | Paths, hex strings, or metadata needed by the harness. |
| `outputs` | object | Expected outputs for positive cases or `{}` for negative cases. |

Additional fields are allowed only when the harness ignores them safely and the
manifest still passes `manifest-rules.jq`.

## Positive and Negative Cases

Positive cases prove compatibility with known vectors and must include expected
outputs. Negative cases prove fail-closed behavior and must name the expected
error class. Invalid-length negative cases should use the same field names as
the Rust errors, for example `ml_kem_768.public_key` or
`ml_dsa_65.signature`.

## Validation

Before adding or changing a manifest, run:

```sh
jq -e -f tests/kat/manifest-rules.jq tests/kat/sample-manifest.json
```

Replace `sample-manifest.json` with the algorithm manifest being reviewed.
