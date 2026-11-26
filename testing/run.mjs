// Runs every scenario of every setup with one package manager version.
//
// Usage:
//   node testing/run.mjs --manager pnpm --version 11.29.0 --fixtures <dir> --out <dir> [--node <path>]
//
// --node is the Node.js binary the package manager runs on (default: `node` on PATH).
// This script itself only needs a recent Node.js. Results go to
// <out>/<manager>-<version>.json and full logs to <out>/logs/<manager>-<version>/.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  MIN_RELEASE_AGE_DAYS,
  ageInDays,
  installPackageManager,
  isolatedEnv,
  parseArgs,
  readJson,
  run,
  unique,
  writeJson,
} from "./lib/common.mjs";
import { SCENARIOS, setupById } from "./lib/setups.mjs";

// A failure caused by the package manager or Node.js version, devEngines, or pmOnFail.
const ENGINE_PATTERNS = [
  /EBADENGINE/,
  /EBADDEVENGINES/,
  /\bENOTSUP\b/,
  /npm (?:ERR!|error) notsup/,
  /Unsupported engine/i,
  /Not compatible with your version of node\/npm/i,
  /ERR_PNPM_UNSUPPORTED_ENGINE/,
  /ERR_PNPM_BAD_PM_VERSION/,
  /ERR_PNPM_[A-Z_]*PACKAGE_MANAGER[A-Z_]*/,
  /Your pnpm version is incompatible/i,
  /This project is configured to use/i,
  /Unsupported (?:package manager|pnpm version)/i,
];

// A failure caused by the release-age settings.
const AGE_PATTERNS = [
  /\bETARGET\b/,
  /with a date before/i,
  /ERR_PNPM_NO_MATURE_MATCHING_VERSION/,
  /ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION/,
  /minimumReleaseAge/,
  /min-release-age/,
  /does not meet the minimumReleaseAge/i,
];

const KNOWN_NPM_CODES = /\b(EBADENGINE|EBADDEVENGINES|ENOTSUP|ETARGET|EUSAGE|ENOLOCK|E404|ENOVERSIONS|EINTEGRITY|ECONNRESET|ENOTFOUND|ENOENT|EACCES|EEXIST|ERESOLVE|EALLOWGIT|EALLOWREMOTE)\b/;

const RELEVANT_LINE = /(ERR_PNPM_[A-Z_]+|npm (?:ERR!|error) |\bError\b|\[ERROR\]|^\s*[×╰]|was published at|Expected version|Got: |Required: |Actual: |configured to use|Your current pnpm|No matching version|Unsupported|Cannot find|TypeError|SyntaxError)/;

function errorCode(output) {
  return (
    /\b(ERR_PNPM_[A-Z0-9_]+)\b/.exec(output)?.[1] ??
    /npm (?:ERR!|error) code (\S+)/.exec(output)?.[1] ??
    KNOWN_NPM_CODES.exec(output)?.[1] ??
    null
  );
}

function excerpt(output) {
  const allLines = output.split(/\r?\n/).map(line => line.trimEnd()).filter(line => line.trim() !== "");
  const relevant = allLines.filter(line => RELEVANT_LINE.test(line));
  const chosen = relevant.length > 0 ? relevant.slice(0, 10) : allLines.slice(-10);
  return chosen.map(line => (line.length > 300 ? `${line.slice(0, 297)}...` : line));
}

function classify(result) {
  if (result.exitCode === 0) {
    return "ok";
  }
  if (result.timedOut) {
    return "timeout";
  }
  if (ENGINE_PATTERNS.some(pattern => pattern.test(result.output))) {
    return "engine-blocked";
  }
  if (AGE_PATTERNS.some(pattern => pattern.test(result.output))) {
    return "age-blocked";
  }
  return "failed";
}

function readVersion(file) {
  try {
    const version = JSON.parse(fs.readFileSync(file, "utf8")).version;
    return typeof version === "string" ? version : null;
  } catch {
    return null;
  }
}

function readPerformer(modulesFile) {
  try {
    const text = fs.readFileSync(modulesFile, "utf8");
    return /["']?packageManager["']?\s*:\s*["']?pnpm@([^"'\s,}]+)/.exec(text)?.[1] ?? null;
  } catch {
    return null;
  }
}

// Finds the test package from `cwd` up to the fixture root, the way Node.js
// resolves it, plus every copy in pnpm's virtual store.
function inspectInstall(root, cwd, pkg) {
  const pkgPath = pkg.split("/");
  const storePrefix = `${pkg.replace("/", "+")}@`;
  const versions = new Set();
  let resolved = null;
  let performer = null;

  for (let dir = cwd; ; dir = path.dirname(dir)) {
    const nodeModules = path.join(dir, "node_modules");
    const direct = readVersion(path.join(nodeModules, ...pkgPath, "package.json"));
    if (direct) {
      versions.add(direct);
      resolved ??= direct;
    }

    const store = path.join(nodeModules, ".pnpm");
    if (fs.existsSync(store)) {
      for (const entry of fs.readdirSync(store)) {
        if (entry.startsWith(storePrefix)) {
          const version = readVersion(path.join(store, entry, "node_modules", ...pkgPath, "package.json"));
          if (version) {
            versions.add(version);
          }
        }
      }
    }

    performer ??= readPerformer(path.join(nodeModules, ".modules.yaml"));

    if (path.relative(root, dir) === "" || !dir.startsWith(root)) {
      break;
    }
  }

  return { resolved, versions: [...versions], performer };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ["manager", "version", "fixtures", "out"]) {
    if (!args[required]) {
      throw new Error(`Missing --${required}`);
    }
  }

  const manager = args.manager;
  const version = args.version;
  const fixtures = path.resolve(args.fixtures);
  const out = path.resolve(args.out);
  const name = `${manager}-${version}`;
  const manifest = readJson(path.join(fixtures, "manifest.json"));
  const context = manifest.context;
  const times = manifest.package.times;
  const work = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP ?? os.tmpdir(), `pm-${name}-`));
  const logDir = path.join(out, "logs", name);

  const testNode = args.node
    ? path.resolve(args.node)
    : run("/bin/sh", ["-c", "command -v node"], { cwd: work, env: process.env }).output.trim();
  const testNodeDir = path.dirname(testNode);

  const report = {
    schemaVersion: 1,
    manager,
    version,
    node: run(testNode, ["--version"], { cwd: work, env: process.env }).output.trim(),
    reportedVersion: null,
    installError: null,
    startedAt: new Date().toISOString(),
    results: [],
  };

  let tool;
  try {
    tool = installPackageManager({
      manager,
      version,
      prefix: path.join(work, "pm"),
      home: path.join(work, "home-install"),
    });
    const check = run(tool.bin, ["--version"], {
      cwd: work,
      env: isolatedEnv({ home: path.join(work, "home-version"), pathDirs: [tool.binDir, testNodeDir] }),
    });
    report.reportedVersion = check.output.trim().split(/\r?\n/).pop() ?? "";
    if (check.exitCode !== 0) {
      report.installError = `${manager} --version failed on Node.js ${report.node} (exit ${check.exitCode}): ${check.output.trim()}`;
    } else if (report.reportedVersion !== version) {
      report.versionWarning = `${manager} --version printed ${JSON.stringify(check.output.trim())}`;
      console.log(`::warning::${name}: ${report.versionWarning}`);
    }
  } catch (error) {
    report.installError = error instanceof Error ? error.message : String(error);
  }

  if (report.installError) {
    console.log(`::error::${name}: ${report.installError.split("\n")[0]}`);
  }

  const setups = manifest.setups
    .map(entry => setupById(entry.id))
    .filter(setup => setup.manager === manager || manifest.plan.crossManager);

  report.probes = {};

  for (const setup of report.installError ? [] : setups) {
    // Which version actually runs in this project: with pmOnFail: download or
    // devEngines onFail: download, pnpm hands over to the pinned version.
    let effectiveVersion = null;
    if (manager === "pnpm") {
      const probeDir = path.join(work, "probe", setup.id);
      fs.cpSync(path.join(fixtures, setup.id, "mature"), path.join(probeDir, "project"), { recursive: true });
      const probe = run(tool.bin, ["--version"], {
        cwd: path.join(probeDir, "project", setup.cwd),
        env: isolatedEnv({ home: path.join(probeDir, "home"), pathDirs: [tool.binDir, testNodeDir] }),
      });
      const printed = probe.output.trim().split(/\r?\n/).pop() ?? "";
      effectiveVersion = probe.exitCode === 0 && /^\d+\.\d+\.\d+/.test(printed) ? printed : null;
      report.probes[setup.id] = {
        exitCode: probe.exitCode,
        version: effectiveVersion,
        excerpt: probe.exitCode === 0 ? [] : excerpt(probe.output),
      };
      fs.rmSync(probeDir, { recursive: true, force: true });
    }

    for (const scenario of SCENARIOS) {
      const cross = setup.manager !== manager;
      if (cross && scenario.sameManagerOnly) {
        continue;
      }

      const scenarioDir = path.join(work, "runs", setup.id, scenario.id);
      const projectRoot = path.join(scenarioDir, "project");
      const cwd = path.join(projectRoot, setup.cwd);
      fs.cpSync(path.join(fixtures, setup.id, scenario.variant), projectRoot, { recursive: true });

      const commandArgs = scenario.args[manager](context);
      const env = isolatedEnv({
        home: path.join(scenarioDir, "home"),
        pathDirs: [tool.binDir, testNodeDir],
        ci: scenario.ci,
      });

      const result = run(tool.bin, commandArgs, { cwd, env });
      const outcome = classify(result);
      const install = inspectInstall(projectRoot, cwd, context.pkg);
      const now = Date.now();
      const isFresh = installed =>
        Boolean(times[installed]) && ageInDays(times[installed], now) < MIN_RELEASE_AGE_DAYS;
      const freshVersions = install.versions.filter(isFresh);
      // installed:  the command succeeded and the project loads a fresh version
      // linked:     the command failed, but the project still loads a fresh version
      // store-only: a fresh version was extracted into node_modules/.pnpm only;
      //             require() from the project does not reach it
      const fresh = install.resolved && isFresh(install.resolved)
        ? result.exitCode === 0 ? "installed" : "linked"
        : freshVersions.length > 0 ? "store-only" : "none";
      const ran = result.exitCode === 0 || install.versions.length > 0;
      const performer = !ran
        ? null
        : manager === "npm"
          ? { version, source: "npm does not switch versions" }
          : install.performer
            ? { version: install.performer, source: "node_modules/.modules.yaml" }
            : effectiveVersion
              ? { version: effectiveVersion, source: "pnpm --version in the project" }
              : { version, source: "assumed" };
      const command = `${manager} ${commandArgs.join(" ")}`;

      const logFile = path.join(logDir, setup.id, `${scenario.id}.log`);
      fs.mkdirSync(path.dirname(logFile), { recursive: true });
      fs.writeFileSync(logFile, [
        `$ cd ${setup.cwd} && ${scenario.ci ? "CI=true " : ""}${command}`,
        `# ${manager} ${version} on Node.js ${report.node}`,
        `# exit ${result.exitCode}${result.signal ? ` (signal ${result.signal})` : ""}${result.timedOut ? " (timed out)" : ""} after ${result.durationMs} ms`,
        "",
        result.output,
        result.spawnError ? `\n# spawn error: ${result.spawnError}` : "",
        `# ${context.pkg} on disk: ${install.versions.join(", ") || "none"}; resolved from cwd: ${install.resolved ?? "none"}; fresh: ${fresh}`,
        `# version that ran: ${performer ? `${performer.version} (${performer.source})` : "nothing was installed"}`,
        "",
      ].join("\n"));

      const entry = {
        setup: setup.id,
        setupManager: setup.manager,
        scenario: scenario.id,
        cwd: setup.cwd,
        command,
        ci: scenario.ci,
        exitCode: result.exitCode,
        signal: result.signal,
        timedOut: result.timedOut,
        durationMs: result.durationMs,
        outcome,
        errorCode: result.exitCode === 0 ? null : errorCode(result.output),
        excerpt: result.exitCode === 0 ? [] : excerpt(result.output),
        resolved: install.resolved,
        versionsOnDisk: install.versions,
        freshVersions,
        fresh,
        ran,
        performer: performer?.version ?? null,
        performerSource: performer?.source ?? null,
        log: path.relative(out, logFile),
      };
      report.results.push(entry);

      console.log([
        `${setup.id.padEnd(32)} ${scenario.id.padEnd(14)} exit=${String(result.exitCode).padEnd(4)}`,
        `${outcome.padEnd(15)} on disk: ${install.versions.join(",") || "-"}`,
        entry.fresh !== "none" ? `FRESH (${entry.fresh})` : "",
        entry.performer && entry.performer !== version ? `ran as ${entry.performer}` : "",
        entry.errorCode ?? "",
      ].filter(Boolean).join("  "));

      fs.rmSync(scenarioDir, { recursive: true, force: true });
    }
  }

  report.finishedAt = new Date().toISOString();
  writeJson(path.join(out, `${name}.json`), report);
  fs.rmSync(work, { recursive: true, force: true });

  const fresh = report.results.filter(entry => entry.fresh !== "none");
  console.log(`\n${name}: ${report.results.length} runs, ${fresh.length} with a fresh ${context.pkg} on disk: ${unique(fresh.map(entry => `${entry.setup}/${entry.scenario}`)).join(", ") || "none"}`);
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
}
