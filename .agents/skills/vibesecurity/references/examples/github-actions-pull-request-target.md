# GitHub Actions Pull Request Target

Vulnerable pattern:

```yaml
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: npm install && npm test
```

Safe pattern:

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

Review lesson: `pull_request_target` runs with trusted context. Do not check out and execute attacker-controlled fork code with elevated secrets or permissions.
