# bcc-security-scan
Collection of reusable workflows for scanning BCC repositories.


### Software supply chain protections check

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
