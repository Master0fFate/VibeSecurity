# Release checklist

Every tagged VibeSecurity release must pass every item. A release that cannot
check an item is not shippable; fix or explicitly defer with a tracked issue.

## Code and tests

- [ ] `python -B .agents/skills/vibesecurity/tests/run_tests.py` passes on Windows, macOS, and Linux (CI matrix green).
- [ ] `python -m compileall -q .agents/skills/vibesecurity/scripts .agents/skills/vibesecurity/tests` succeeds.
- [ ] Secret-corpus scores printed by the suite meet or exceed the committed targets (recall ≥ 0.9, precision ≥ 0.9) — record the printed numbers in the release notes.
- [ ] No bundled matcher example failures (the gate test is part of the suite).
- [ ] A live `feed refresh` + `scan --fail-on confirmed` round-trip was executed once by a maintainer against a sample repository, and the `advisory_db` provenance block was inspected.

## Versioning and schema

- [ ] `VIBESEC_VERSION` in `scripts/vibesecurity_common.py`, `metadata.version` in `SKILL.md`, and the version pin in `tests/test_hardening_behaviors.py` all match the tag.
- [ ] `CHANGELOG.md` has an entry for the tag with the date and corpus scores.
- [ ] Matcher/finding/baseline/config schema versions are unchanged unless the release notes say otherwise; schema changes are additive-minor or breaking-major with migration notes.

## Advisories and data

- [ ] A fresh `advisory-bundle.json` was exported after the last OSV/KEV refresh cycle used for verification, and `scan --advisory-db` consumes it cleanly (checksums verify).
- [ ] The staleness downgrade path was demonstrated once with a deliberately aged cache.

## Security of the artifact

- [ ] `git grep` over the release diff shows no credential values, no real tokens, and no unresolved `[source needed]` markers in user-facing docs.
- [ ] Release archive (if published) carries a sha256 checksum; signing is optional and documented when absent.

## Docs

- [ ] README command table matches the helper `--help` output.
- [ ] `docs/ENTERPRISE-UPGRADE-PROGRAM.md` implementation status markers updated for this release.
- [ ] Integration recipes still match the exit-code contract.

## Tag

- [ ] Tag is annotated (`git tag -a`), named `vX.Y.Z`, and pushed with the release notes attached.
