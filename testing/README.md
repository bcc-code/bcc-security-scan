# Package manager version tests

This branch (`testing-v1`) tests the supply-chain policy from `policy-v1` against real
npm and pnpm releases. For every version in [`versions/npm.txt`](versions/npm.txt) and
[`versions/pnpm.txt`](versions/pnpm.txt) it answers two questions in every project
setup the policy accepts:

1. **Is the version allowed to install?** Or does `engines`, `devEngines`, or `pmOnFail`
   stop it?
2. **Does it install a dependency version younger than 7 days?**

The workflow is [`.github/workflows/package-manager-tests.yml`](../.github/workflows/package-manager-tests.yml).

## Running it

- **Push to `testing-v1`** (changes under `testing/` or the workflow): runs a sample.
  The sample is the newest version of each major, plus the versions on both sides of
  the policy minimums (npm 11.10.0, pnpm 11.0.0), plus the pnpm pin.
- **Actions → Package manager version tests → Run workflow** on `testing-v1`: runs
  every listed version by default. Inputs:

  | Input | Default | Meaning |
  | --- | --- | --- |
  | `scope` | `full` | `full` or `sample` |
  | `managers` | `both` | `both`, `npm` or `pnpm` |
  | `versions` | | Only these, e.g. `npm@11.21.3 pnpm@11.29.0` |
  | `test-package` | | Package to install (see [Test package](#test-package)) |
  | `pnpm-pin` | | Exact pnpm version the devEngines setups pin |
  | `node-version` | | One Node.js version for every job, instead of one per major |
  | `cross-manager` | `true` | Also run npm in pnpm setups, and pnpm in npm setups |
  | `fail-on-violation` | `true` | Fail the report job when a result contradicts the policy |

  From a terminal, use `gh workflow run package-manager-tests.yml --ref testing-v1 -f scope=full`.

To add or remove versions, edit the version lists. One job runs per version, and
GitHub allows at most 256 jobs per matrix.

## What a run does

1. **Prepare.** Picks the test package, the pnpm pin, and the lockfile generators.
   It then writes every setup's fixtures twice. One copy locks the *mature* version
   of the test package; the other locks the *fresh* version. Lockfiles are written
   with the release-age settings switched off, as a developer or a dependency bot
   could do.
2. **Policy check.** Runs the real `supply-chain-protections/check` action on every
   fixture. A setup the policy rejects is flagged in the report and fails the run,
   because its results would not describe an accepted setup.
3. **One job per version.** Installs that npm or pnpm release with
   `npm install --global` into its own prefix. Then it runs every scenario of every
   setup. Each scenario gets a fresh copy of the fixture, an empty home folder and
   cache, and only that package manager and Node.js on `PATH`.
4. **Report.** Writes the job summary, plus `report.md`, `results.csv` (one row per
   command) and `summary.json`, to the `package-manager-test-report` artifact. Full
   logs of every command are in the `pm-<manager>-<version>` artifacts.

### Setups

All of them pass `policy-v1`; see [`lib/setups.mjs`](lib/setups.mjs) for the exact files.

| Setup | Layout | Versions the policy means to allow |
| --- | --- | --- |
| `npm-single` | package.json, `.npmrc` with the required settings, package-lock.json | npm >= 11.10.0 |
| `npm-dev-engines` | as above, plus `devEngines.packageManager` `>=11.10.0`, `onFail: error` | npm >= 11.10.0 |
| `npm-workspace` | npm workspaces; commands run in `packages/app` | npm >= 11.10.0 |
| `npm-parent-npmrc` | `app/` has package.json and lockfile; the only `.npmrc` is in the root | npm >= 11.10.0 |
| `pnpm-single` | `engines`, `.npmrc` with `engine-strict`, the required `pnpm-workspace.yaml` settings, `pmOnFail: error` | pnpm >= 11.0.0 |
| `pnpm-dev-engines-range` | as above, plus `devEngines.packageManager` `>=11.0.0` | pnpm >= 11.0.0 |
| `pnpm-pin-error` | `devEngines.packageManager` pinned to an exact version, `pmOnFail: error` | the pin only |
| `pnpm-pin-download` | exact pin, `pmOnFail: download` | the pin only (others may hand over to it) |
| `pnpm-pin-onfail-download` | exact pin with `onFail: download`, `pmOnFail: error` | the pin only (others may hand over to it) |
| `pnpm-workspace` | pnpm workspace; commands run in `packages/app` | pnpm >= 11.0.0 |
| `pnpm-workspace-no-root-manifest` | workspace without a root package.json; commands run in `app` | pnpm >= 11.0.0 |

For cross-manager runs, npm in any pnpm setup must be refused (`engines.npm=disallow`).
pnpm in an npm setup is reported, but the policy does not cover it, so it never counts
as a gap.

### Scenarios

| Letter | Scenario | Command |
| --- | --- | --- |
| `i` | Install from the committed lockfile (mature version) | `npm install` / `pnpm install` |
| `f` | Add the fresh version explicitly | `npm install <pkg>@<fresh>` / `pnpm add <pkg>@<fresh>` |
| `l` | Add the latest version (the latest dist-tag is fresh) | `npm install <pkg>@latest` / `pnpm add <pkg>@latest` |
| `c` | CI install of a lockfile that pins the fresh version | `CI=true npm ci` / `CI=true pnpm install --frozen-lockfile` |

After each command, the runner checks `node_modules` itself rather than relying on
the exit code:

- **installed**: the command succeeded, and the project loads a fresh version.
- **linked**: the command failed, but the project still loads a fresh version.
- **store only**: a fresh version was extracted into `node_modules/.pnpm`, but
  `require()` from the project does not reach it.

The version that actually ran is read from `node_modules/.modules.yaml` (pnpm), or from
`pnpm --version` in the project. This catches pnpm handing over to the pinned version.

### What counts as a gap

A result is a **policy gap** (❗) when, in a setup the policy accepts:

- a version outside the intended range ran and installed dependencies; or
- a fresh dependency version was installed, or left loadable after a failed command.

A version the policy means to allow, but which was refused, is an **unexpected block**
(⁉️). That does not weaken security, but the policy or a fixture probably needs a look.

## Test package

The fresh version must be younger than 7 days throughout the run, so the package
must publish often. It must also have no dependencies and no install scripts, so
nothing else affects the result. By default the first suitable package of
`electron-to-chromium` and `caniuse-lite` is used:

- **fresh**: its `latest` version, younger than 6 days;
- **mature**: its newest version at least 8 days old.

A package is skipped when the latest version has weaker provenance than earlier
ones, because pnpm's `trustPolicy: no-downgrade` would block it for a different
reason.

The pnpm pin defaults to the newest listed pnpm >= 11.0.0 that is at least 7 days
old. With `pmOnFail: download`, pnpm applies `minimumReleaseAge` to the pnpm it
downloads, so a younger pin could not be fetched.

## Node.js versions

Each package manager runs on the Node.js line of its time. It does not use the host
Node.js, which only runs the test scripts.

| Package manager | Node.js |
| --- | --- |
| npm 2 | 4 |
| npm 5 | 8 |
| npm 6 | 14 |
| npm 7, pnpm 7 | 16 |
| npm 8, pnpm 8 | 18 |
| npm 9, pnpm 9 | 20 |
| npm 10, pnpm 10 | 22 |
| npm 11 and 12, pnpm 11 and 12 | 24 |

Use the `node-version` input to run everything on one Node.js version.

## Running locally

Node.js 22.13 or newer, network access to registry.npmjs.org:

```bash
SCOPE=sample node testing/prepare.mjs --out /tmp/pm/fixtures
```

```bash
node testing/run.mjs --manager pnpm --version 11.29.0 --fixtures /tmp/pm/fixtures --out /tmp/pm/results
```

```bash
node testing/report.mjs --fixtures /tmp/pm/fixtures --results /tmp/pm/results --policy /tmp/pm/policy --out /tmp/pm/report
```

Locally, `run.mjs` runs the package manager on whichever `node` is on `PATH`; pass
`--node` to choose another. The policy check needs the GitHub workflow, so a local
report shows every setup as "not checked".
