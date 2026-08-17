# Jenkins integration

Declarative pipeline step:

```groovy
pipeline {
  agent any
  options { timestamps(); timeout(time: 10, unit: 'MINUTES') }
  stages {
    stage('VibeSecurity') {
      steps {
        sh 'python3 -B .agents/skills/vibesecurity/scripts/vibesecurity.py feed refresh --root . || true'
        sh '''
          python3 -B .agents/skills/vibesecurity/scripts/vibesecurity.py scan --root . \
            --fail-on confirmed-high
        '''
      }
    }
  }
}
```

Exit codes: 0 clean · 1 findings at/above threshold · 2 tool error · 3 usage error.

Notes:

- `sh` fails the build on exit 1 and 2, which is the desired default: findings above threshold and tool failures both stop the pipeline.
- The `|| true` on `feed refresh` is optional; it makes network-restricted agents degrade to no-advisory scanning instead of failing. Prefer removing it when egress is allowed.
- For agents without egress, export a bundle elsewhere and add `--advisory-db advisories/advisory-bundle.json` to `scan`.
- Windows agents: replace `sh`/`python3` with `bat`/`py -3 -B`; command semantics are identical.
