# Repository Settings

This document records the intended GitHub repository settings for PQC Bridge.

## General

- Repository: `VrianCao/pqc-bridge`
- Visibility: public
- Default branch: `main`
- Issues: enabled
- Discussions: enabled
- Projects: enabled
- Wiki: disabled
- Delete branch on merge: enabled

## Merge Policy

Recommended:

- squash merge enabled
- merge commits disabled
- rebase merge disabled
- auto-merge enabled
- update branch enabled

## Branch Protection

Recommended for `main`:

- require pull request before merge
- require approving review
- dismiss stale approvals
- require conversation resolution
- require status checks
- require branches to be up to date
- block force pushes
- block deletions

## Security

Recommended:

- private vulnerability reporting enabled
- Dependabot alerts enabled
- Dependabot security updates enabled
- secret scanning enabled
- secret scanning push protection enabled where available
- CodeQL enabled
- Scorecard workflow enabled

Some settings depend on GitHub plan availability and repository permissions.
