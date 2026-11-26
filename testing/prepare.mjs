// Prepares a package manager test run:
//   1. picks the test package and its fresh and mature versions,
//   2. picks the exact pnpm version that devEngines fixtures pin,
//   3. generates every setup's fixtures, with lockfiles,
//   4. plans the job matrices and writes them as GitHub outputs.
//
// Usage: node testing/prepare.mjs --out <dir>
// Settings come from environment variables (all optional):
//   SCOPE          full (default) or sample
//   MANAGERS       both (default), npm or pnpm
//   VERSIONS       e.g. "npm@11.21.3 pnpm@11.29.0", runs only these
//   TEST_PACKAGE   test package; empty tries the default candidates
//   PNPM_PIN       exact pnpm version for devEngines pins; empty picks one
//   NPM_GENERATOR  npm version that writes the npm lockfiles; empty picks one
//   NODE_VERSION   Node.js version for every job; empty maps by major version
//   CROSS_MANAGER  true (default) also runs each manager on the other's setups
//   POLICY_REF     policy branch the fixtures are checked against (default policy-v1)

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  MIN_RELEASE_AGE_DAYS,
  ageInDays,
  atLeast,
  compareVersions,
  fetchPackument,
  installPackageManager,
  isolatedEnv,
  majorOf,
  parseArgs,
  parseVersion,
  readVersionList,
  run,
  unique,
  writeFiles,
  writeJson,
} from "./lib/common.mjs";
import { NPM_MINIMUM, PNPM_MINIMUM, SCENARIOS, SETUPS } from "./lib/setups.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

// Frequently published packages without dependencies or install scripts.
const DEFAULT_PACKAGES = ["electron-to-chromium", "caniuse-lite"];

// The fresh version must stay younger than 7 days for the whole run,
// and the mature version must be clearly older.
const FRESH_MAX_AGE_DAYS = 6;
const MATURE_MIN_AGE_DAYS = 8;

// Node.js major for each package manager major: the line that shipped with, or was
// current for, that release. Override with NODE_VERSION.
const NODE_BY_MAJOR = {
  npm: { 5: "8", 6: "14", 7: "16", 8: "18", 9: "20", 10: "22", 11: "24", 12: "24" },
  pnpm: { 6: "14", 7: "16", 8: "18", 9: "20", 10: "22", 11: "24", 12: "24" },
};

const MATRIX_LIMIT = 256;

const MINIMUM = { npm: NPM_MINIMUM, pnpm: PNPM_MINIMUM };

function setting(name, fallback = "") {
  const value = process.env[name];
  return value === undefined || value.trim() === "" ? fallback : value.trim();
}

function notice(level, message) {
  if (process.env.GITHUB_ACTIONS === "true") {
    console.log(`::${level}::${message.replaceAll("%", "%25").replaceAll("\n", "%0A")}`);
  } else {
    console.log(`${level}: ${message}`);
  }
}

function trustLevel(manifest) {
  if (manifest?._npmUser?.trustedPublisher) {
    return 2;
  }
  return manifest?.dist?.attestations ? 1 : 0;
}

async function choosePackage(candidates, now) {
  const problems = [];

  for (const name of candidates) {
    const doc = await fetchPackument(name);
    const age = version => ageInDays(doc.time[version], now);
    const latest = doc["dist-tags"]?.latest;

    if (!latest || !doc.time?.[latest]) {
      problems.push(`${name}: no latest dist-tag`);
      continue;
    }
    if (age(latest) >= FRESH_MAX_AGE_DAYS) {
      problems.push(`${name}: latest (${latest}) is ${age(latest).toFixed(1)} days old, not younger than ${FRESH_MAX_AGE_DAYS}`);
      continue;
    }

    const stable = Object.keys(doc.versions).filter(version =>
      parseVersion(version)?.prerelease === "" && doc.time[version]);
    const mature = stable
      .filter(version => age(version) >= MATURE_MIN_AGE_DAYS)
      .sort(compareVersions)
      .pop();

    if (!mature) {
      problems.push(`${name}: no version is at least ${MATURE_MIN_AGE_DAYS} days old`);
      continue;
    }

    const unsuitable = [latest, mature].flatMap(version => {
      const manifest = doc.versions[version];
      const reasons = [];
      for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
        if (Object.keys(manifest[field] ?? {}).length > 0) {
          reasons.push(`${version} has ${field}`);
        }
      }
      for (const script of ["preinstall", "install", "postinstall"]) {
        if (manifest.scripts?.[script]) {
          reasons.push(`${version} has a ${script} script`);
        }
      }
      return reasons;
    });
    if (unsuitable.length > 0) {
      problems.push(`${name}: ${unsuitable.join(", ")}`);
      continue;
    }

    // pnpm's trustPolicy: no-downgrade would block the fresh version for another
    // reason than its age, which would hide what the release-age settings do.
    const earlierTrust = Math.max(0, ...stable
      .filter(version => Date.parse(doc.time[version]) < Date.parse(doc.time[latest]))
      .map(version => trustLevel(doc.versions[version])));
    if (trustLevel(doc.versions[latest]) < earlierTrust) {
      problems.push(`${name}: ${latest} was published with weaker provenance than earlier versions`);
      continue;
    }

    const times = {};
    for (const version of Object.keys(doc.versions)) {
      if (doc.time[version]) {
        times[version] = doc.time[version];
      }
    }

    return { name, fresh: latest, mature, times };
  }

  throw new Error(`No suitable test package:\n  ${problems.join("\n  ")}`);
}

function parseVersionOverrides(text) {
  const selected = { npm: [], pnpm: [] };
  for (const token of text.split(/[\s,]+/).filter(Boolean)) {
    const match = /^(npm|pnpm)@(.+)$/.exec(token);
    if (!match) {
      throw new Error(`VERSIONS entries must look like npm@1.2.3 or pnpm@1.2.3, got ${token}`);
    }
    selected[match[1]].push(match[2]);
  }
  return selected;
}

// The newest version of each major, plus the versions on both sides of the
// policy minimum, plus any extra versions (the pnpm pin).
function sample(versions, minimum, extra = []) {
  const picked = new Set(extra.filter(version => versions.includes(version)));
  const byMajor = new Map();
  for (const version of versions) {
    const major = majorOf(version);
    if (!byMajor.has(major) || compareVersions(version, byMajor.get(major)) > 0) {
      byMajor.set(major, version);
    }
  }
  for (const version of byMajor.values()) {
    picked.add(version);
  }
  const sorted = [...versions].sort(compareVersions);
  const lowestAllowed = sorted.find(version => atLeast(version, minimum));
  const highestDisallowed = sorted.filter(version => !atLeast(version, minimum)).pop();
  for (const version of [lowestAllowed, highestDisallowed]) {
    if (version) {
      picked.add(version);
    }
  }
  return versions.filter(version => picked.has(version));
}

function newestMature(versions, doc, minimum, now) {
  return versions
    .filter(version => atLeast(version, minimum))
    .filter(version => doc.time?.[version] && ageInDays(doc.time[version], now) >= MIN_RELEASE_AGE_DAYS)
    .sort(compareVersions)
    .pop();
}

function nodeFor(manager, version, override) {
  return override || NODE_BY_MAJOR[manager][majorOf(version)] || "24";
}

function copyDirectory(source, destination) {
  fs.cpSync(source, destination, { recursive: true });
}

function removeFiles(root, name) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      removeFiles(full, name);
    } else if (entry.name === name) {
      fs.rmSync(full);
    }
  }
}

// Writes the lockfile with the protections relaxed, so a lockfile that pins a fresh
// version can be produced, as it would be by a developer or a dependency update bot.
function generateLockfile({ setup, fixture, generators, work, context, spec }) {
  const scratch = path.join(work, "lock", `${setup.id}-${spec}`);
  fs.rmSync(scratch, { recursive: true, force: true });
  copyDirectory(fixture, scratch);

  const home = path.join(work, "home", `${setup.id}-${spec}`);
  const tool = generators[setup.manager];
  let args;

  if (setup.manager === "npm") {
    // Without .npmrc: no min-release-age, no engine-strict.
    removeFiles(scratch, ".npmrc");
    args = ["install", "--package-lock-only", "--ignore-scripts"];
  } else {
    const workspaceFile = path.join(scratch, "pnpm-workspace.yaml");
    const text = fs.readFileSync(workspaceFile, "utf8");
    fs.writeFileSync(
      workspaceFile,
      text.replace(/^minimumReleaseAge: .*$/m, "minimumReleaseAge: 0"),
    );
    args = ["install", "--lockfile-only", "--no-frozen-lockfile"];
  }

  const result = run(tool.bin, args, {
    cwd: path.join(scratch, setup.lockDir),
    env: isolatedEnv({ home, pathDirs: [tool.binDir, path.dirname(process.execPath)] }),
  });

  const lockfile = path.join(scratch, setup.lockfile);
  if (result.exitCode !== 0 || !fs.existsSync(lockfile)) {
    throw new Error(
      `Generating ${setup.lockfile} for ${setup.id} (${context.pkg}@${spec}) failed (exit ${result.exitCode}):\n${result.output}`,
    );
  }

  const text = fs.readFileSync(lockfile, "utf8");
  if (!text.includes(spec)) {
    throw new Error(`${setup.id}: ${setup.lockfile} does not lock ${context.pkg}@${spec}`);
  }

  fs.copyFileSync(lockfile, path.join(fixture, setup.lockfile));
  fs.rmSync(scratch, { recursive: true, force: true });
}

function appendOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  const line = `${name}=${value}\n`;
  if (file) {
    fs.appendFileSync(file, line);
  } else {
    process.stdout.write(line);
  }
}

function appendSummary(markdown) {
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.out) {
    throw new Error("Usage: node testing/prepare.mjs --out <dir>");
  }

  const out = path.resolve(args.out);
  const now = Date.now();
  const scope = setting("SCOPE", "full");
  const managers = setting("MANAGERS", "both");
  const crossManager = setting("CROSS_MANAGER", "true") === "true";
  const nodeOverride = setting("NODE_VERSION");
  const work = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP ?? os.tmpdir(), "pm-prepare-"));

  if (!["full", "sample"].includes(scope)) {
    throw new Error(`SCOPE must be full or sample, got ${scope}`);
  }
  if (!["both", "npm", "pnpm"].includes(managers)) {
    throw new Error(`MANAGERS must be both, npm or pnpm, got ${managers}`);
  }

  const listed = {
    npm: readVersionList(path.join(here, "versions", "npm.txt")),
    pnpm: readVersionList(path.join(here, "versions", "pnpm.txt")),
  };
  const registry = {
    npm: await fetchPackument("npm"),
    pnpm: await fetchPackument("pnpm"),
  };

  const pkg = await choosePackage(
    setting("TEST_PACKAGE") ? [setting("TEST_PACKAGE")] : DEFAULT_PACKAGES,
    now,
  );

  const pin = setting("PNPM_PIN") || newestMature(listed.pnpm, registry.pnpm, PNPM_MINIMUM, now);
  if (!pin || !registry.pnpm.versions[pin]) {
    throw new Error(`pnpm pin ${pin} does not exist`);
  }
  if (ageInDays(registry.pnpm.time[pin], now) < MIN_RELEASE_AGE_DAYS) {
    notice("warning", `pnpm ${pin} is younger than ${MIN_RELEASE_AGE_DAYS} days; pmOnFail: download cannot fetch it until it matures.`);
  }

  const npmGenerator = setting("NPM_GENERATOR") || newestMature(listed.npm, registry.npm, NPM_MINIMUM, now);
  if (!npmGenerator || !registry.npm.versions[npmGenerator]) {
    throw new Error(`npm generator ${npmGenerator} does not exist`);
  }

  const context = { pkg: pkg.name, fresh: pkg.fresh, mature: pkg.mature, pin };

  // Plan the matrices.
  const overrides = parseVersionOverrides(setting("VERSIONS"));
  const useOverrides = overrides.npm.length + overrides.pnpm.length > 0;
  const plan = { npm: [], pnpm: [] };
  const skipped = [];

  for (const manager of ["npm", "pnpm"]) {
    if (managers !== "both" && managers !== manager) {
      continue;
    }
    let versions = useOverrides ? overrides[manager] : listed[manager];
    if (!useOverrides && scope === "sample") {
      versions = sample(versions, MINIMUM[manager], manager === "pnpm" ? [pin] : []);
    }
    for (const version of unique(versions)) {
      if (!registry[manager].versions[version]) {
        skipped.push({ manager, version, reason: "not published in the npm registry" });
        notice("warning", `${manager}@${version} is not published; skipping it.`);
        continue;
      }
      plan[manager].push({ manager, version, node: nodeFor(manager, version, nodeOverride) });
    }
    if (plan[manager].length > MATRIX_LIMIT) {
      throw new Error(`${plan[manager].length} ${manager} versions exceed the ${MATRIX_LIMIT}-job matrix limit; split the run with VERSIONS.`);
    }
  }

  // Generate the fixtures.
  console.log(`Installing lockfile generators npm@${npmGenerator} and pnpm@${pin}`);
  const generators = {
    npm: installPackageManager({
      manager: "npm",
      version: npmGenerator,
      prefix: path.join(work, "pm", `npm-${npmGenerator}`),
      home: path.join(work, "home", "install-npm"),
    }),
    pnpm: installPackageManager({
      manager: "pnpm",
      version: pin,
      prefix: path.join(work, "pm", `pnpm-${pin}`),
      home: path.join(work, "home", "install-pnpm"),
    }),
  };

  fs.rmSync(out, { recursive: true, force: true });
  for (const setup of SETUPS) {
    for (const [variant, spec] of [["mature", pkg.mature], ["fresh", pkg.fresh]]) {
      console.log(`Generating ${setup.id}/${variant} (${pkg.name}@${spec})`);
      const fixture = path.join(out, setup.id, variant);
      writeFiles(fixture, setup.files(context, spec));
      generateLockfile({ setup, fixture, generators, work, context, spec });
    }
  }

  const manifest = {
    schemaVersion: 1,
    createdAt: new Date(now).toISOString(),
    policyBranch: setting("POLICY_REF", "policy-v1"),
    context,
    package: {
      name: pkg.name,
      fresh: { version: pkg.fresh, published: pkg.times[pkg.fresh] },
      mature: { version: pkg.mature, published: pkg.times[pkg.mature] },
      times: pkg.times,
    },
    generators: { npm: npmGenerator, pnpm: pin },
    setups: SETUPS.map(({ id, manager, policy, rejectedWith, title, notes, cwd, node, expects }) =>
      ({ id, manager, policy, rejectedWith, title, notes, cwd, node: node ?? null, expects })),
    scenarios: SCENARIOS.map(({ id, short, title, notes, variant, ci, sameManagerOnly }) =>
      ({ id, short, title, notes, variant, ci, sameManagerOnly: Boolean(sameManagerOnly) })),
    plan: { scope: useOverrides ? "custom" : scope, managers, crossManager, nodeOverride, skipped, ...plan },
  };
  writeJson(path.join(out, "manifest.json"), manifest);
  fs.rmSync(work, { recursive: true, force: true });

  appendOutput("npm", JSON.stringify(plan.npm));
  appendOutput("pnpm", JSON.stringify(plan.pnpm));
  appendOutput("setups", JSON.stringify(SETUPS.map(setup => ({ id: setup.id, policy: setup.policy }))));

  const age = version => ageInDays(pkg.times[version], now).toFixed(1);
  const summary = [
    "### Package manager test plan",
    "",
    `- Test package: \`${pkg.name}\`, fresh \`${pkg.fresh}\` (${age(pkg.fresh)} days old), mature \`${pkg.mature}\` (${age(pkg.mature)} days old)`,
    `- Exact pnpm version in devEngines pins: \`${pin}\``,
    `- Lockfiles written by npm \`${npmGenerator}\` and pnpm \`${pin}\``,
    `- Scope: ${manifest.plan.scope}; ${plan.npm.length} npm and ${plan.pnpm.length} pnpm versions; cross-manager runs: ${crossManager ? "yes" : "no"}`,
    ...skipped.map(entry => `- Skipped ${entry.manager}@${entry.version}: ${entry.reason}`),
    "",
  ].join("\n");
  appendSummary(`${summary}\n`);
  console.log(summary);
}

main().catch(error => {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
});
