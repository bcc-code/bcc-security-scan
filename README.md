# bcc-security-scan
Collection of reusable workflows for scanning BCC repositories.


### Software supply chain protections check

```yaml
name: Supply-chain security

on:
  pull_request:
  push:
    branches: [main]

permissions: {}

jobs:
  supply-chain:
    permissions:
      contents: read
    uses: bcc-code/bcc-security-scan/supply-chain-protections.yml@<40_CHARACTER_SHA>
    with:
      fail-on-warn: true
```
