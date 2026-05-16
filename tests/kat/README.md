# Known-Answer Tests

This directory is reserved for known-answer tests.

All production backend integrations must include KAT coverage before release.

Expected future layout:

```text
tests/kat/
  ml-kem-768/
  ml-dsa-65/
  slh-dsa/
  hybrid/
```

Test vectors should record:

- source
- algorithm
- parameter set
- upstream version
- generation method
- license or redistribution terms
- checksum
