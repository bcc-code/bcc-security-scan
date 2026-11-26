// Project setups and scenarios for the package manager tests.
//
// Setups with policy "accept" are layouts that the supply-chain policy on the
// policy-v1 branch accepts; every package manager version runs against them.
// Setups with policy "reject" are layouts that earlier versions of the policy
// accepted although package managers ignored their settings; the policy must now
// reject them, with a message containing `rejectedWith`. They are only policy-checked.
// The workflow checks each generated fixture with the real check action, and the
// report flags any setup the policy treats differently, so a policy change cannot
// quietly turn these into tests of layouts the policy no longer allows.

import { atLeast, majorOf } from "./common.mjs";

// The minimum versions the policy requires (npm_minimum_version and
// pnpm_minimum_version in javascript.rego). pnpm 11.1.3 is the first version
// that rejects a lockfile pinning a version younger than minimumReleaseAge.
export const NPM_MINIMUM = "11.10.0";
export const PNPM_MINIMUM = "11.1.3";

const lines = (...values) => `${values.join("\n")}\n`;

// The settings javascript/npmrc-* requires in npm projects.
const NPMRC_FOR_NPM = lines(
  "engine-strict=true",
  "allow-git=root",
  "allow-remote=root",
  "ignore-scripts=true",
  "min-release-age=7",
);

// javascript/pnpm-npmrc-engine-strict: npm must refuse engines.npm=disallow.
const NPMRC_FOR_PNPM = lines("engine-strict=true");

// The settings javascript/pnpm-workspace-* requires.
function pnpmWorkspace({ packages = [], pmOnFail = "error" } = {}) {
  const packageLines = packages.length === 0
    ? ["packages: []"]
    : ["packages:", ...packages.map(entry => `  - ${JSON.stringify(entry)}`)];
  return lines(
    ...packageLines,
    "engineStrict: true",
    "minimumReleaseAge: 10080",
    "minimumReleaseAgeStrict: true",
    "blockExoticSubdeps: true",
    "strictDepBuilds: true",
    "trustPolicy: no-downgrade",
    `pmOnFail: ${pmOnFail}`,
  );
}

function manifest(name, fields) {
  return { name, version: "1.0.0", private: true, ...fields };
}

const npmEngines = { npm: `>=${NPM_MINIMUM}` };
const pnpmEngines = { npm: "disallow", pnpm: `>=${PNPM_MINIMUM}` };

function devEnginesNpmMinimumFiles(context, spec) {
  return {
    "package.json": manifest("fixture", {
      engines: { npm: ">=10.9.0", pnpm: `>=${PNPM_MINIMUM}` },
      devEngines: { packageManager: { name: "pnpm", version: context.pin } },
      dependencies: { [context.pkg]: spec },
    }),
    ".npmrc": NPMRC_FOR_PNPM,
    "pnpm-workspace.yaml": pnpmWorkspace(),
  };
}

function devEnginesNode22Files(context, spec) {
  return {
    "package.json": manifest("fixture", {
      engines: { node: ">=22.10.0" },
      devEngines: { packageManager: { name: "pnpm", version: context.pin } },
      dependencies: { [context.pkg]: spec },
    }),
    ".npmrc": NPMRC_FOR_PNPM,
    "pnpm-workspace.yaml": pnpmWorkspace(),
  };
}

const npmVersionAllowed = performer => atLeast(performer, NPM_MINIMUM);
const pnpmVersionAllowed = performer => atLeast(performer, PNPM_MINIMUM);

// Fields of a setup:
//   id, manager, title, notes
//   policy   "accept" or "reject" (see above); rejectedWith for "reject"
//   cwd      where the scenario commands run, relative to the fixture root
//   lockDir  where the lockfile is generated, relative to the fixture root
//   lockfile path of the lockfile, relative to the fixture root
//   node     "host" runs every version on the job's host Node.js (24) instead of
//            the Node.js line of the version's time
//   expects  human-readable rule for which package manager version may install
//   allows(performer, context)  that rule as a function
//   files(context, spec)        the fixture's files; spec is the test package's version
export const SETUPS = [
  {
    id: "npm-single",
    manager: "npm",
    policy: "accept",
    title: "npm, single package",
    notes: "package.json, .npmrc and package-lock.json in one folder.",
    cwd: ".",
    lockDir: ".",
    lockfile: "package-lock.json",
    expects: `npm >= ${NPM_MINIMUM}`,
    allows: npmVersionAllowed,
    files: (context, spec) => ({
      "package.json": manifest("fixture", {
        engines: npmEngines,
        dependencies: { [context.pkg]: spec },
      }),
      ".npmrc": NPMRC_FOR_NPM,
    }),
  },
  {
    id: "npm-dev-engines",
    manager: "npm",
    policy: "accept",
    title: "npm, devEngines.packageManager",
    notes: `As npm-single, plus devEngines.packageManager {name: npm, version: ">=${NPM_MINIMUM}", onFail: error}.`,
    cwd: ".",
    lockDir: ".",
    lockfile: "package-lock.json",
    expects: `npm >= ${NPM_MINIMUM}`,
    allows: npmVersionAllowed,
    files: (context, spec) => ({
      "package.json": manifest("fixture", {
        engines: npmEngines,
        devEngines: {
          packageManager: { name: "npm", version: `>=${NPM_MINIMUM}`, onFail: "error" },
        },
        dependencies: { [context.pkg]: spec },
      }),
      ".npmrc": NPMRC_FOR_NPM,
    }),
  },
  {
    id: "npm-workspace",
    manager: "npm",
    policy: "accept",
    title: "npm workspaces, run in a workspace package",
    notes: "Root package.json with workspaces, root .npmrc and package-lock.json; packages/app has its own .npmrc too. Commands run in packages/app.",
    cwd: "packages/app",
    lockDir: ".",
    lockfile: "package-lock.json",
    expects: `npm >= ${NPM_MINIMUM}`,
    allows: npmVersionAllowed,
    files: (context, spec) => ({
      "package.json": manifest("fixture-root", {
        workspaces: ["packages/*"],
        engines: npmEngines,
      }),
      ".npmrc": NPMRC_FOR_NPM,
      "packages/app/package.json": manifest("app", {
        engines: npmEngines,
        dependencies: { [context.pkg]: spec },
      }),
      "packages/app/.npmrc": NPMRC_FOR_NPM,
    }),
  },
  {
    id: "npm-parent-npmrc",
    manager: "npm",
    policy: "reject",
    rejectedWith: "app/.npmrc must exist",
    title: "npm, .npmrc only in a parent folder",
    notes: "app/package.json and app/package-lock.json; the only .npmrc is in the repository root. npm ignores it, so every npm version installed fresh versions here.",
    cwd: "app",
    lockDir: "app",
    lockfile: "app/package-lock.json",
    expects: `npm >= ${NPM_MINIMUM}`,
    allows: npmVersionAllowed,
    files: (context, spec) => ({
      ".npmrc": NPMRC_FOR_NPM,
      "app/package.json": manifest("app", {
        engines: npmEngines,
        dependencies: { [context.pkg]: spec },
      }),
    }),
  },
  {
    id: "pnpm-single",
    manager: "pnpm",
    policy: "accept",
    title: "pnpm, single package, pmOnFail: error",
    notes: "engines.pnpm and engines.npm=disallow, .npmrc with engine-strict, the required pnpm-workspace.yaml settings, no devEngines.",
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: `pnpm >= ${PNPM_MINIMUM}`,
    allows: pnpmVersionAllowed,
    files: (context, spec) => ({
      "package.json": manifest("fixture", {
        engines: pnpmEngines,
        dependencies: { [context.pkg]: spec },
      }),
      ".npmrc": NPMRC_FOR_PNPM,
      "pnpm-workspace.yaml": pnpmWorkspace(),
    }),
  },
  {
    id: "pnpm-dev-engines-range",
    manager: "pnpm",
    policy: "accept",
    title: "pnpm, devEngines range, pmOnFail: error",
    notes: `As pnpm-single, plus devEngines.packageManager {name: pnpm, version: ">=${PNPM_MINIMUM}"}.`,
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: `pnpm >= ${PNPM_MINIMUM}`,
    allows: pnpmVersionAllowed,
    files: (context, spec) => ({
      "package.json": manifest("fixture", {
        engines: pnpmEngines,
        devEngines: { packageManager: { name: "pnpm", version: `>=${PNPM_MINIMUM}` } },
        dependencies: { [context.pkg]: spec },
      }),
      ".npmrc": NPMRC_FOR_PNPM,
      "pnpm-workspace.yaml": pnpmWorkspace(),
    }),
  },
  {
    id: "pnpm-pin-error",
    manager: "pnpm",
    policy: "accept",
    title: "pnpm, devEngines exact pin, pmOnFail: error",
    notes: "As pnpm-single, plus devEngines.packageManager pinned to the exact pin version. Other versions must stop.",
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: "pnpm == pin",
    allows: (performer, context) => performer === context.pin,
    files: (context, spec) => ({
      "package.json": manifest("fixture", {
        engines: pnpmEngines,
        devEngines: { packageManager: { name: "pnpm", version: context.pin } },
        dependencies: { [context.pkg]: spec },
      }),
      ".npmrc": NPMRC_FOR_PNPM,
      "pnpm-workspace.yaml": pnpmWorkspace(),
    }),
  },
  {
    id: "pnpm-pin-download",
    manager: "pnpm",
    policy: "accept",
    title: "pnpm, devEngines exact pin, pmOnFail: download",
    notes: "devEngines.packageManager pinned to the pin version; pmOnFail: download makes other versions switch to it.",
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: "pnpm == pin (other versions stop or switch to it)",
    allows: (performer, context) => performer === context.pin,
    files: (context, spec) => ({
      "package.json": manifest("fixture", {
        engines: pnpmEngines,
        devEngines: { packageManager: { name: "pnpm", version: context.pin } },
        dependencies: { [context.pkg]: spec },
      }),
      ".npmrc": NPMRC_FOR_PNPM,
      "pnpm-workspace.yaml": pnpmWorkspace({ pmOnFail: "download" }),
    }),
  },
  {
    id: "pnpm-pin-onfail-download",
    manager: "pnpm",
    policy: "accept",
    title: "pnpm, devEngines exact pin with onFail: download, pmOnFail: error",
    notes: "devEngines.packageManager {version: pin, onFail: download} with pmOnFail: error.",
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: "pnpm == pin (other versions stop or switch to it)",
    allows: (performer, context) => performer === context.pin,
    files: (context, spec) => ({
      "package.json": manifest("fixture", {
        engines: pnpmEngines,
        devEngines: {
          packageManager: { name: "pnpm", version: context.pin, onFail: "download" },
        },
        dependencies: { [context.pkg]: spec },
      }),
      ".npmrc": NPMRC_FOR_PNPM,
      "pnpm-workspace.yaml": pnpmWorkspace(),
    }),
  },
  // With an exact pnpm pin in devEngines, policy-v1 accepts engines.npm with a minimum
  // of 10.9.0 instead of disallow, so consumers of a published package can still use npm.
  // npm 10.9 and newer refuse devEngines naming pnpm; engine-strict stops older npm.
  {
    id: "pnpm-dev-engines-npm-minimum",
    manager: "pnpm",
    policy: "accept",
    title: "pnpm, devEngines pin with engines.npm >=10.9.0 instead of disallow",
    notes: "devEngines.packageManager pinned to the pin version, engines.npm >=10.9.0 and engines.pnpm, no engines.node; .npmrc with engine-strict; pmOnFail: error. Each version runs on its usual Node.js.",
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: "pnpm == pin",
    allows: (performer, context) => performer === context.pin,
    files: devEnginesNpmMinimumFiles,
  },
  {
    id: "pnpm-dev-engines-npm-minimum-on-node24",
    manager: "pnpm",
    policy: "accept",
    title: "As pnpm-dev-engines-npm-minimum, with every version on Node.js 24",
    notes: "The same files, but every npm and pnpm version runs on Node.js 24, as when a developer upgrades Node.js and keeps an older npm or pnpm.",
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    node: "host",
    expects: "pnpm == pin",
    allows: (performer, context) => performer === context.pin,
    files: devEnginesNpmMinimumFiles,
  },
  // The layout PR #13 accepted: engines.node >= 22.10.0 and a devEngines pin, with no
  // engines.npm or engines.pnpm. On Node.js 22.23, npm 7 to 10.8 and pnpm 9 and 10 ignored
  // the pin and installed fresh versions, so the policy must reject it.
  {
    id: "pnpm-dev-engines-node22",
    manager: "pnpm",
    policy: "reject",
    rejectedWith: "must set engines.npm=disallow",
    title: "pnpm, devEngines pin and engines.node instead of engines.npm/pnpm",
    notes: "engines.node >=22.10.0 and devEngines.packageManager pinned, no engines.npm or engines.pnpm. npm 7 to 10.8 and pnpm 9 and 10 ignore devEngines and run on Node.js 22.10 and newer, so they installed fresh versions here.",
    cwd: ".",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: "pnpm == pin",
    allows: (performer, context) => performer === context.pin,
    files: devEnginesNode22Files,
  },
  {
    id: "pnpm-workspace",
    manager: "pnpm",
    policy: "accept",
    title: "pnpm workspace, run in a workspace package",
    notes: "Root package.json with engines.pnpm, pnpm-workspace.yaml listing packages/*; packages/app has engines.npm=disallow and its own .npmrc. Commands run in packages/app.",
    cwd: "packages/app",
    lockDir: ".",
    lockfile: "pnpm-lock.yaml",
    expects: `pnpm >= ${PNPM_MINIMUM}`,
    allows: pnpmVersionAllowed,
    files: (context, spec) => ({
      "package.json": manifest("fixture-root", { engines: pnpmEngines }),
      ".npmrc": NPMRC_FOR_PNPM,
      "pnpm-workspace.yaml": pnpmWorkspace({ packages: ["packages/*"] }),
      "packages/app/package.json": manifest("app", {
        engines: { npm: "disallow" },
        dependencies: { [context.pkg]: spec },
      }),
      "packages/app/.npmrc": NPMRC_FOR_PNPM,
    }),
  },
  {
    id: "pnpm-workspace-no-root-manifest",
    manager: "pnpm",
    policy: "reject",
    rejectedWith: "package.json must exist next to pnpm-workspace.yaml",
    title: "pnpm workspace without a root package.json",
    notes: "pnpm-workspace.yaml and pnpm-lock.yaml in the root, no root package.json; app has engines.npm=disallow and its own .npmrc. Nothing sets engines.pnpm, so pnpm 7 to 10 installed fresh versions here.",
    cwd: "app",
    // pnpm needs a package.json to run in; it finds the workspace root from here.
    lockDir: "app",
    lockfile: "pnpm-lock.yaml",
    expects: `pnpm >= ${PNPM_MINIMUM}`,
    allows: pnpmVersionAllowed,
    files: (context, spec) => ({
      "pnpm-workspace.yaml": pnpmWorkspace({ packages: ["app"] }),
      "app/package.json": manifest("app", {
        engines: { npm: "disallow" },
        dependencies: { [context.pkg]: spec },
      }),
      "app/.npmrc": NPMRC_FOR_PNPM,
    }),
  },
];

// Scenarios run against every setup. Each runs in a fresh copy of the fixture
// with an empty cache and home folder.
//   variant  which fixture: "mature" locks the mature version, "fresh" locks the fresh one
//   ci       sets CI=true, as on a CI runner (pnpm then refuses to change the lockfile)
//   sameManagerOnly  skipped when testing the other manager's setups (it needs that manager's lockfile)
export const SCENARIOS = [
  {
    id: "install",
    short: "i",
    title: "Install from the committed lockfile",
    notes: "npm install / pnpm install on the fixture that locks the mature version, as a developer would. Shows whether the version is allowed to install at all.",
    variant: "mature",
    ci: false,
    args: { npm: () => ["install"], pnpm: () => ["install"] },
  },
  {
    id: "add-fresh",
    short: "f",
    title: "Add the fresh version explicitly",
    notes: "npm install <pkg>@<fresh> / pnpm add <pkg>@<fresh>.",
    variant: "mature",
    ci: false,
    args: {
      npm: context => ["install", `${context.pkg}@${context.fresh}`],
      pnpm: context => ["add", `${context.pkg}@${context.fresh}`],
    },
  },
  {
    id: "add-latest",
    short: "l",
    title: "Add the latest version",
    notes: "npm install <pkg>@latest / pnpm add <pkg>@latest; the latest dist-tag points at a fresh version. A protected install picks the newest version older than 7 days instead. (Without @latest, npm and pnpm keep the version already locked.)",
    variant: "mature",
    ci: false,
    args: {
      npm: context => ["install", `${context.pkg}@latest`],
      pnpm: context => ["add", `${context.pkg}@latest`],
    },
  },
  {
    id: "ci-fresh-lock",
    short: "c",
    title: "CI install of a lockfile that pins the fresh version",
    notes: "npm ci / pnpm install --frozen-lockfile with CI=true, on a committed lockfile that pins the fresh version (as a dependency update PR would).",
    variant: "fresh",
    ci: true,
    sameManagerOnly: true,
    args: { npm: () => ["ci"], pnpm: () => ["install", "--frozen-lockfile"] },
  },
];

// Gaps the policy cannot close, because no file in a repository changes the package
// manager's behaviour. The report lists them separately and does not fail on them.
// Keep the matches narrow: any other gap still fails the run.
//   manager       the package manager that runs
//   setupManager  the manager of the setups it applies to (null: any)
//   versions      which versions of `manager` it applies to
//   scenarios, kinds  which findings it explains (kinds as in report.mjs)
export const KNOWN_GAPS = [
  {
    id: "npm-ci-installs-locked-fresh-versions",
    manager: "npm",
    setupManager: "npm",
    versions: () => true,
    scenarios: ["ci-fresh-lock"],
    kinds: ["fresh-installed"],
    reason: "npm applies min-release-age only when it resolves a version; npm ci installs whatever package-lock.json pins. The policy keeps accepting npm and says so in its javascript/prefer-pnpm warning.",
  },
  {
    id: "npm-6-ignores-engines-for-named-installs",
    manager: "npm",
    setupManager: null,
    versions: version => majorOf(version) !== null && majorOf(version) < 7,
    scenarios: ["add-fresh", "add-latest"],
    kinds: ["disallowed-version", "fresh-installed"],
    reason: "npm 6 and older check engines.npm only on a plain npm install, not when installing a named package, and do not know min-release-age. Nothing in a repository stops them locally; in CI the policy allows only npm ci.",
  },
  {
    id: "pnpm-11-links-before-the-lockfile-check-fails",
    manager: "pnpm",
    setupManager: "pnpm",
    versions: version => atLeast(version, "11.7.0") && !atLeast(version, "12.0.0"),
    scenarios: ["ci-fresh-lock"],
    kinds: ["fresh-linked"],
    reason: "pnpm 11.7 and later 11.x releases reject the lockfile, so the install fails, but can link the fresh version into node_modules before the check finishes. pnpm 12 leaves it only in node_modules/.pnpm.",
  },
];

export function knownGap(manager, version, setup, kind, scenario) {
  return KNOWN_GAPS.find(gap =>
    gap.manager === manager &&
    (gap.setupManager === null || gap.setupManager === setup.manager) &&
    gap.scenarios.includes(scenario) &&
    gap.kinds.includes(kind) &&
    gap.versions(version)) ?? null;
}

// Which package manager versions the policy means to allow when `manager` runs in
// `setup`. Returns null when the policy does not cover the combination.
export function expectationFor(manager, setup) {
  if (manager === setup.manager) {
    return { rule: setup.expects, allows: setup.allows };
  }
  if (manager === "npm" && setup.manager === "pnpm") {
    // javascript/pnpm-disallow-npm and javascript/pnpm-npmrc-engine-strict.
    return { rule: "npm must not run (engines.npm=disallow)", allows: () => false };
  }
  return null;
}

export function setupById(id) {
  const setup = SETUPS.find(candidate => candidate.id === id);
  if (!setup) {
    throw new Error(`Unknown setup: ${id}`);
  }
  return setup;
}
