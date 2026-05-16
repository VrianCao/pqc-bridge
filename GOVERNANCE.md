# Governance

PQC Bridge starts as a maintainer-led project. The governance model should
evolve as contributors, users, and security reviewers join.

## Maintainer Responsibilities

Maintainers are responsible for:

- preserving the project security model
- reviewing API compatibility
- approving backend integrations
- managing releases
- coordinating vulnerability handling
- keeping documentation accurate

## Decision Process

Security-sensitive decisions should be documented in RFCs under `docs/rfcs/`.

Examples:

- default backend selection
- key envelope changes
- high-level protocol composition
- C ABI memory ownership changes
- v1.0 compatibility policy

## Backend Approval

A backend should not become default until it has:

- clear license compatibility
- upstream maintenance confidence
- KAT coverage
- platform support notes
- side-channel claim documentation
- review by at least two maintainers or trusted reviewers

## Release Authority

Stable releases should require:

- passing CI
- changelog update
- signed tag or release artifact plan
- security review for sensitive changes
- documented compatibility notes
