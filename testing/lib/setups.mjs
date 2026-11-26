// Project setups and scenarios for the package manager tests.
//
// Every setup is a layout that the supply-chain policy on the policy-v1 branch
// accepts. The workflow checks each generated fixture with the real check action,
// and the report flags any setup the policy rejects, so a policy change cannot
// quietly turn these into tests of layouts the policy no longer allows.

import { atLeast } from "./common.mjs";

// The minimum versions the policy requires (javascript/minimum-npm-version and
// javascript/minimum-pnpm-version).
export const NPM_MINIMUM = "11.10.0";
export const PNPM_MINIMUM = "11.0.0";

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

const npmVersionAllowed = performer => atLeast(performer, NPM_MINIMUM);
const pnpmVersionAllowed = performer => atLeast(performer, PNPM_MINIMUM);

// Fields of a setup:
//   id, manager, title, notes
//   cwd      where the scenario commands run, relative to the fixture root
//   lockDir  where the lockfile is generated, relative to the fixture root
//   lockfile path of the lockfile, relative to the fixture root
//   expects  human-readable rule for which package manager version may install
//   allows(performer, context)  that rule as a function
//   files(context, spec)        the fixture's files; spec is the test package's version
export const SETUPS = [
  {
    id: "npm-single",
    manager: "npm",
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
    title: "npm workspaces, run in a workspace package",
    notes: "Root package.json with workspaces, root .npmrc and package-lock.json; commands run in packages/app.",
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
    }),
  },
  {
    id: "npm-parent-npmrc",
    manager: "npm",
    title: "npm, .npmrc in a parent folder",
    notes: "app/package.json and app/package-lock.json; the only .npmrc is in the repository root, which the policy accepts as the closest one.",
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
  {
    id: "pnpm-workspace",
    manager: "pnpm",
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
    title: "pnpm workspace without a root package.json",
    notes: "pnpm-workspace.yaml and pnpm-lock.yaml in the root, no root package.json; app has engines.npm=disallow and its own .npmrc. The policy only requires engines.pnpm in the workspace package, which does not exist here.",
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
