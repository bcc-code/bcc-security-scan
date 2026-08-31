# bcc-security-scan
Collection of reusable workflows for scanning BCC repositories.

## Software supply chain protections check

### Usage

Add a workflow such as `.github/workflows/supply-chain-security.yml` to the
repository being checked. Replace `<40_CHARACTER_SHA>` with the full commit SHA
of the version of the latest release.

```yaml
name: Supply-chain security

on:
  pull_request:
    branches: [main, master]
    paths: &supply-chain-paths
      - '.github/workflows/**'
      - '**/action.yml'
      - '**/action.yaml'
      - '**/package.json'
      - '**/package-lock.json'
      - '**/pnpm-lock.yaml'
      - '**/pnpm-workspace.yaml'
      - '**/.npmrc'
      - '**/yarn.lock'
      - '**/bun.lock'
      - '**/bun.lockb'
      - '**/deno.lock'
      - '**/Dockerfile'
      - '**/Dockerfile.*'
      - '**/*.Dockerfile'
      - '**/.dockerignore'
  push:
    branches: [main, master]
    paths: *supply-chain-paths
  workflow_dispatch:

permissions: {}

jobs:
  supply-chain:
    permissions:
      contents: read
    uses: bcc-code/bcc-security-scan/.github/workflows/supply-chain-protections.yml@<40_CHARACTER_SHA>
    with:
      fail-on-warn: true
```

The `fail-on-warn` input defaults to `false`. Set it to `true` to make policy
warnings fail the job in addition to policy errors.

### How it works

The reusable workflow runs one `check` job on `ubuntu-24.04` with read-only
access to repository contents. It performs these steps:

1. Checks out the repository with persisted credentials disabled and a shallow
   clone.
2. Runs the composite policy-check action, which generates a **JSON inventory**
   of the checked-out repository and parses relevant files
   (see [./supply-chain-protections/inventory](./supply-chain-protections/inventory)).
3. Evaluates that inventory against the supply-chain policies using Conftest.
4. Fails the job with Conftest's exit code when the policy evaluation does not
   succeed.

#### Repository inventory

The inventory action recursively scans the repository, excluding `.git`,
`node_modules`, `dist`, `build`, and `coverage` directories and ignoring
symbolic links. The generated inventory contains:

- All scanned file paths.
- JavaScript projects discovered from `package.json`, including the detected
  package manager, nearest relevant lockfile, `.npmrc`, and pnpm workspace
  configuration.
- GitHub Actions workflow and action YAML documents.
- Shell commands and environment values from workflow steps, composite actions,
  and Dockerfile `RUN` instructions, associated with the nearest project.
- Docker build inputs inferred from `COPY` instructions after applying the
  relevant `.dockerignore`; sources copied from another build stage are skipped.

The action prints this JSON inventory in a collapsed workflow log group for
troubleshooting.

#### Policy evaluation and reporting

The check downloads Conftest `0.69.0`, verifies the archive against a pinned
SHA-256 checksum, and adds the binary to the job path. It then downloads the
**`policy-v1`** branch of this repository and runs policies in the
`supply_chain.*` namespace against the inventory.

Conftest writes its findings as SARIF. The action converts those findings into
GitHub error, warning, and notice annotations and adds file-and-line links to
the job summary. Unpinned workflow-dependency findings are grouped into a
collapsible summary; when there are more than seven, only the first three are
also emitted as annotations to keep the workflow log readable.

The composite action exposes the SARIF file path and Conftest exit code as
`sarif` and `exit_code` outputs. The reusable workflow uses `exit_code` to
enforce the result even when the evaluation produced findings.
