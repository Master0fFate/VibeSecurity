# pre-commit integration

Run the agent-side review cheaply on changed files. Two options:

## Local hook (changed files only)

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: vibesecurity-diff
        name: vibesecurity diff inventory
        entry: python -B .agents/skills/vibesecurity/scripts/vibesecurity.py diff --root .
        language: system
        pass_filenames: false
        stages: [pre-commit]
```

The `diff` command is inventory-only and exits 0 unless the tool itself fails (exit 2); it never blocks on candidates. Review the output before committing — candidates still require validation.

## Full scan hook (gated)

```yaml
      - id: vibesecurity-scan
        name: vibesecurity scan
        entry: python -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root . --fail-on confirmed-high
        language: system
        pass_filenames: false
        stages: [pre-push]
```

Run the gated variant at `pre-push`, not `pre-commit`: a full scan with an advisory cache can take longer than a commit should.

Notes:

- `feed refresh` is a separate manual or scheduled step; the cache under `.vibesecurity/cache/` is read offline by `scan`.
- `--fail-on` acts on confirmed findings only; needs-review candidates never block a push.
