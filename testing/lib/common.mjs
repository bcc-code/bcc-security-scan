// Shared helpers for the package manager tests. No dependencies: these scripts
// run before anything is installed, on the host Node.js of the job.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const DAY_MS = 24 * 60 * 60 * 1000;

// The policy's minimum release age (7 days, or 10,080 minutes).
export const MIN_RELEASE_AGE_DAYS = 7;

export const REGISTRY = "https://registry.npmjs.org";

// Variables passed through to package manager commands, so the tests also work
// behind a proxy. GitHub-hosted runners set none of them.
const PASS_THROUGH_ENV = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "npm_config_proxy",
  "npm_config_https_proxy",
  "npm_config_noproxy",
  "npm_config_cafile",
];

export function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      throw new Error(`Unexpected argument: ${arg}`);
    }
    const [key, inline] = arg.slice(2).split("=", 2);
    if (inline !== undefined) {
      args[key] = inline;
    } else if (index + 1 < argv.length && !argv[index + 1].startsWith("--")) {
      args[key] = argv[index + 1];
      index += 1;
    } else {
      args[key] = "true";
    }
  }
  return args;
}

export function parseVersion(version) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/.exec(
    String(version).trim(),
  );
  if (!match) {
    return null;
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? "",
  };
}

export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) {
    return String(left).localeCompare(String(right));
  }
  for (const key of ["major", "minor", "patch"]) {
    if (a[key] !== b[key]) {
      return a[key] - b[key];
    }
  }
  if (a.prerelease === b.prerelease) {
    return 0;
  }
  if (a.prerelease === "") {
    return 1;
  }
  if (b.prerelease === "") {
    return -1;
  }
  return a.prerelease.localeCompare(b.prerelease);
}

export function atLeast(version, minimum) {
  return parseVersion(version) !== null && compareVersions(version, minimum) >= 0;
}

export function majorOf(version) {
  return parseVersion(version)?.major ?? null;
}

export function readVersionList(file) {
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map(line => line.replace(/#.*/, "").trim())
    .filter(Boolean);
}

export function unique(values) {
  return [...new Set(values)];
}

export async function fetchPackument(name) {
  const url = `${REGISTRY}/${name.replace("/", "%2F")}`;
  // Full metadata: abbreviated documents do not include publish times.
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`GET ${url} failed: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

export function ageInDays(isoTime, now = Date.now()) {
  return (now - Date.parse(isoTime)) / DAY_MS;
}

export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

export function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function writeFiles(root, files) {
  for (const [file, content] of Object.entries(files)) {
    const destination = path.join(root, ...file.split("/"));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    const text = typeof content === "string"
      ? content
      : `${JSON.stringify(content, null, 2)}\n`;
    fs.writeFileSync(destination, text);
  }
}

// Environment for a package manager command: nothing inherited from the job
// except proxy settings, so runner defaults (CI=true, npm_config_*, a global
// pnpm) cannot change the result.
export function isolatedEnv({ home, pathDirs, ci = false, extra = {} }) {
  const env = {
    PATH: [...pathDirs, "/usr/bin", "/bin"].join(path.delimiter),
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
    TMPDIR: path.join(home, "tmp"),
    LANG: "C.UTF-8",
    TERM: "dumb",
    NO_COLOR: "1",
    FORCE_COLOR: "0",
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_update_notifier: "false",
    npm_config_progress: "false",
    ...extra,
  };
  for (const key of PASS_THROUGH_ENV) {
    if (process.env[key] !== undefined) {
      env[key] = process.env[key];
    }
  }
  if (ci) {
    env.CI = "true";
  }
  for (const dir of [env.XDG_CONFIG_HOME, env.XDG_CACHE_HOME, env.XDG_DATA_HOME, env.XDG_STATE_HOME, env.TMPDIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return env;
}

// Runs a command and returns its combined output in order.
export function run(command, args, { cwd, env, timeoutMs = 5 * 60 * 1000 }) {
  const started = Date.now();
  const result = spawnSync(
    "/bin/sh",
    ["-c", 'exec "$0" "$@" 2>&1', command, ...args],
    {
      cwd,
      env,
      encoding: "utf8",
      timeout: timeoutMs,
      killSignal: "SIGKILL",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  const timedOut = result.error?.code === "ETIMEDOUT";
  return {
    exitCode: result.status,
    signal: result.signal,
    timedOut,
    spawnError: result.error && !timedOut ? String(result.error.message) : null,
    output: result.stdout ?? "",
    durationMs: Date.now() - started,
  };
}

// Installs a package manager release the way users do, with `npm install --global`
// into its own prefix, using the job's host npm. This also runs pnpm 12's install
// script, which places its native binary.
export function installPackageManager({ manager, version, prefix, hostNode = process.execPath, home }) {
  const hostNpm = path.join(path.dirname(hostNode), "npm");
  fs.mkdirSync(prefix, { recursive: true });
  const env = isolatedEnv({
    home,
    pathDirs: [path.dirname(hostNode)],
  });
  const result = run(
    hostNpm,
    [
      "install",
      "--global",
      "--prefix",
      prefix,
      "--no-audit",
      "--no-fund",
      "--loglevel=error",
      `${manager}@${version}`,
    ],
    { cwd: prefix, env, timeoutMs: 10 * 60 * 1000 },
  );
  if (result.exitCode !== 0) {
    throw new Error(
      `Installing ${manager}@${version} failed (exit ${result.exitCode}):\n${result.output}`,
    );
  }
  const bin = path.join(prefix, "bin", manager);
  if (!fs.existsSync(bin)) {
    throw new Error(`Installing ${manager}@${version} did not create ${bin}`);
  }
  return { bin, binDir: path.join(prefix, "bin") };
}

export function escapeMarkdown(text) {
  return String(text).replaceAll("|", "\\|").replaceAll("\n", " ");
}
