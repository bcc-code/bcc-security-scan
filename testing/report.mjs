// Combines the policy checks of the fixtures and the results of every package
// manager version into a Markdown report, a CSV of every command, and a JSON summary.
//
// Usage:
//   node testing/report.mjs --fixtures <dir> --results <dir> --policy <dir> --out <dir>
//     [--fail-on-violation true] [--require-policy true]

import fs from "node:fs";
import path from "node:path";
import {
  ageInDays,
  compareVersions,
  escapeMarkdown,
  parseArgs,
  readJson,
  unique,
  writeJson,
} from "./lib/common.mjs";
import { SCENARIOS, expectationFor, setupById } from "./lib/setups.mjs";

const SUMMARY_LIMIT = 900 * 1024; // GitHub's step summary limit is 1 MiB.

const STATE_ICON = { allowed: "🟢", switched: "🔁", blocked: "🛑", error: "⚠️" };

const KIND_TEXT = {
  "disallowed-version": "versions the policy means to exclude ran and installed dependencies",
  "fresh-installed": "a dependency version younger than 7 days was installed",
  "fresh-linked": "the command failed, but left a dependency version younger than 7 days loadable in node_modules",
};

const KIND_ORDER = Object.keys(KIND_TEXT);

const short = id => SCENARIOS.find(scenario => scenario.id === id)?.short ?? id;

function readResults(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs.readdirSync(dir)
    .filter(file => file.endsWith(".json"))
    .map(file => readJson(path.join(dir, file)))
    .filter(report => report.schemaVersion === 1 && report.manager && report.version);
}

function readPolicy(dir) {
  const policy = {};
  if (!fs.existsSync(dir)) {
    return policy;
  }
  for (const file of fs.readdirSync(dir).filter(name => name.endsWith(".json"))) {
    const entry = readJson(path.join(dir, file));
    policy[entry.setup] = entry;
  }
  return policy;
}

function policyStatus(check) {
  if (!check) {
    return { accepted: null, text: "not checked" };
  }
  if (check.outcome !== "success") {
    return { accepted: false, text: `check failed (${check.outcome || "no result"})` };
  }
  return String(check.exitCode) === "0"
    ? { accepted: true, text: "accepted" }
    : { accepted: false, text: `rejected (Conftest exit ${check.exitCode})` };
}

function evaluate(report, setup, context) {
  const rows = report.results.filter(row => row.setup === setup.id);
  if (rows.length === 0) {
    return null;
  }

  const tested = report.version;
  const expectation = expectationFor(report.manager, setup);
  const ran = rows.filter(row => row.ran);
  const effective = report.probes?.[setup.id]?.version ?? null;
  let performers = unique(ran.map(row => row.performer));
  let state;

  if (ran.length > 0) {
    state = performers.some(performer => performer !== tested) ? "switched" : "allowed";
  } else if (rows.some(row => row.outcome === "ok" || row.outcome === "age-blocked")) {
    // It resolved dependencies and only the release age stopped it.
    state = effective && effective !== tested ? "switched" : "allowed";
    performers = [effective ?? tested];
  } else if (rows.some(row => row.outcome === "engine-blocked")) {
    state = "blocked";
  } else {
    state = "error";
  }

  const fresh = kind => rows.filter(row => row.fresh === kind).map(row => row.scenario);
  const violations = [];

  if (expectation) {
    const disallowed = ran.filter(row => !expectation.allows(row.performer, context));
    if (disallowed.length > 0) {
      violations.push({
        kind: "disallowed-version",
        scenarios: disallowed.map(row => row.scenario),
        performers: unique(disallowed.map(row => row.performer)),
      });
    }
    for (const kind of ["installed", "linked"]) {
      if (fresh(kind).length > 0) {
        violations.push({ kind: `fresh-${kind}`, scenarios: fresh(kind) });
      }
    }
  }

  const unexpectedBlock = Boolean(expectation) &&
    expectation.allows(tested, context) &&
    (state === "blocked" || state === "error");

  return {
    manager: report.manager,
    version: tested,
    setup: setup.id,
    covered: Boolean(expectation),
    rule: expectation?.rule ?? "not covered by the policy",
    state,
    performers: performers.filter(performer => performer !== tested),
    freshInstalled: fresh("installed"),
    freshLinked: fresh("linked"),
    freshStoreOnly: fresh("store-only"),
    violations,
    unexpectedBlock,
    blockedBy: state === "blocked"
      ? unique(rows.map(row => row.errorCode).filter(Boolean))
      : [],
  };
}

function cell(evaluation) {
  if (!evaluation) {
    return "";
  }
  let text = STATE_ICON[evaluation.state];
  if (evaluation.state === "switched") {
    text += evaluation.performers.join("/");
  }
  const letters = scenarios => scenarios.map(short).join("");
  if (evaluation.freshInstalled.length > 0) {
    text += ` ❌${letters(evaluation.freshInstalled)}`;
  }
  if (evaluation.freshLinked.length > 0) {
    text += ` ✖️${letters(evaluation.freshLinked)}`;
  }
  if (evaluation.freshStoreOnly.length > 0) {
    text += ` 🟠${letters(evaluation.freshStoreOnly)}`;
  }
  if (evaluation.violations.length > 0) {
    text = `❗${text}`;
  }
  if (evaluation.unexpectedBlock) {
    text += " ⁉️";
  }
  return text;
}

function table(header, rows) {
  return [
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
    ...rows.map(row => `| ${row.map(value => escapeMarkdown(value)).join(" | ")} |`),
  ].join("\n");
}

function listVersions(entries) {
  return entries
    .sort((left, right) => compareVersions(right.version, left.version))
    .map(entry => (entry.detail ? `${entry.version} (${entry.detail})` : entry.version))
    .join(", ");
}

function csvValue(value) {
  const text = Array.isArray(value) ? value.join(" ") : value === null || value === undefined ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ["fixtures", "results", "policy", "out"]) {
    if (!args[required]) {
      throw new Error(`Missing --${required}`);
    }
  }
  const failOnViolation = (args["fail-on-violation"] ?? "true") === "true";
  const manifest = readJson(path.join(args.fixtures, "manifest.json"));
  const context = manifest.context;
  const setups = manifest.setups.map(entry => setupById(entry.id));
  const reports = readResults(args.results);
  const policy = readPolicy(args.policy);
  const out = path.resolve(args.out);
  fs.mkdirSync(out, { recursive: true });

  const planned = [...manifest.plan.npm, ...manifest.plan.pnpm];
  const found = new Set(reports.map(report => `${report.manager}@${report.version}`));
  const missing = planned.filter(entry => !found.has(`${entry.manager}@${entry.version}`));
  const installErrors = reports.filter(report => report.installError);

  const evaluations = [];
  for (const report of reports) {
    for (const setup of setups) {
      const evaluation = evaluate(report, setup, context);
      if (evaluation) {
        evaluation.node = report.node;
        evaluations.push(evaluation);
      }
    }
  }

  const policyRows = setups.map(setup => {
    const mature = policyStatus(policy[setup.id]?.mature);
    const fresh = policyStatus(policy[setup.id]?.fresh);
    return { setup, mature, fresh };
  });
  const rejected = policyRows.filter(row => row.mature.accepted === false || row.fresh.accepted === false);
  const unchecked = policyRows.filter(row => row.mature.accepted === null || row.fresh.accepted === null);
  const violations = evaluations.filter(evaluation => evaluation.violations.length > 0);
  const unexpected = evaluations.filter(evaluation => evaluation.unexpectedBlock);

  const lines = [];
  const add = (...values) => lines.push(...values);
  const age = version => ageInDays(manifest.package.times[version], Date.parse(manifest.createdAt)).toFixed(1);
  const runUrl = process.env.GITHUB_RUN_ID
    ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
    : null;

  add(
    "# Package manager version tests",
    "",
    `Policy: \`${manifest.policyBranch}\`. Prepared ${manifest.createdAt}${runUrl ? ` in [this run](${runUrl})` : ""}.`,
    "",
    `- Test package \`${context.pkg}\`: fresh \`${context.fresh}\` (${age(context.fresh)} days old when prepared), mature \`${context.mature}\` (${age(context.mature)} days old).`,
    `- devEngines fixtures pin pnpm \`${context.pin}\`. Lockfiles written by npm \`${manifest.generators.npm}\` and pnpm \`${manifest.generators.pnpm}\` with the release-age settings off.`,
    `- ${reports.length} of ${planned.length} planned versions reported; ${evaluations.length} version-and-setup combinations evaluated.`,
    "",
  );

  // Overall verdict.
  add("## Verdict", "");
  if (violations.length === 0 && rejected.length === 0 && missing.length === 0 && installErrors.length === 0) {
    add("✅ Every tested version behaved as the policy intends in every accepted setup.", "");
  } else {
    if (violations.length > 0) {
      add(`❗ ${violations.length} version-and-setup combinations contradict the policy's intent (see [Policy gaps](#policy-gaps)).`);
    }
    if (rejected.length > 0) {
      add(`❗ The policy rejects ${rejected.length} fixture setups, so their results do not describe accepted setups: ${rejected.map(row => `\`${row.setup.id}\``).join(", ")}.`);
    }
    if (missing.length > 0) {
      add(`⚠️ ${missing.length} planned versions reported no results: ${missing.map(entry => `${entry.manager}@${entry.version}`).join(", ")}.`);
    }
    if (installErrors.length > 0) {
      add(`⚠️ ${installErrors.length} versions could not be installed or run: ${installErrors.map(report => `${report.manager}@${report.version}`).join(", ")}.`);
    }
    add("");
  }
  if (unexpected.length > 0) {
    add(`⁉️ ${unexpected.length} combinations blocked a version the policy means to allow (see [Unexpected blocks](#unexpected-blocks)).`, "");
  }

  // Setups and their policy check.
  add(
    "## Setups",
    "",
    "Every setup is checked with the `supply-chain-protections/check` action against the `policy-v1` policy, once with each lockfile.",
    "",
    table(
      ["Setup", "Manager", "Allowed versions (policy intent)", "Policy check (mature / fresh lock)", "Layout"],
      policyRows.map(({ setup, mature, fresh }) => [
        `\`${setup.id}\``,
        setup.manager,
        setup.expects.replace("pin", `pin (${context.pin})`),
        `${mature.accepted === false ? "❗ " : ""}${mature.text} / ${fresh.text}`,
        setup.notes,
      ]),
    ),
    "",
    "Scenarios, each in a fresh copy of the fixture with an empty cache:",
    "",
    table(
      ["Letter", "Scenario", "What runs"],
      SCENARIOS.map(scenario => [
        scenario.short,
        scenario.title,
        `${scenario.notes}${scenario.sameManagerOnly ? " Only on the manager's own setups." : ""}`,
      ]),
    ),
    "",
    "Cells: 🟢 the version ran; 🔁*x* it handed over to version *x*; 🛑 it refused to run (engines, devEngines or pmOnFail); ⚠️ it failed for another reason.",
    "❌ a fresh version (younger than 7 days) was installed, ✖️ the command failed but left a fresh version loadable in node_modules, 🟠 a fresh version was extracted only into node_modules/.pnpm; followed by the scenario letters.",
    "❗ contradicts the policy's intent; ⁉️ a version the policy means to allow was blocked.",
    "",
  );

  // Per-manager summary and matrix.
  for (const manager of ["npm", "pnpm"]) {
    const managerReports = reports
      .filter(report => report.manager === manager)
      .sort((left, right) => compareVersions(right.version, left.version));
    if (managerReports.length === 0) {
      continue;
    }

    const own = setups.filter(setup => setup.manager === manager);
    const other = setups.filter(setup => setup.manager !== manager);
    const find = (version, setup) =>
      evaluations.find(evaluation =>
        evaluation.manager === manager && evaluation.version === version && evaluation.setup === setup.id);

    add(`## ${manager}`, "", `${managerReports.length} versions. Summary for ${manager}'s own setups:`, "");

    add(table(
      ["Version", "Node.js", "Ran in", "Fresh dependency loadable in", "Result"],
      managerReports.map(report => {
        if (report.installError) {
          return [report.version, report.node, "—", "—", `⚠️ ${report.installError.split("\n")[0].slice(0, 160)}`];
        }
        const own_ = own.map(setup => find(report.version, setup)).filter(Boolean);
        const allowed = own_.filter(evaluation => evaluation.state === "allowed").length;
        const switched = own_.filter(evaluation => evaluation.state === "switched").length;
        const freshIn = own_
          .filter(evaluation => evaluation.freshInstalled.length + evaluation.freshLinked.length > 0)
          .map(evaluation => `${evaluation.setup} (${[...evaluation.freshInstalled, ...evaluation.freshLinked].map(short).join("")})`);
        const all = [...own_, ...other.map(setup => find(report.version, setup)).filter(Boolean)];
        const gaps = all.filter(evaluation => evaluation.violations.length > 0).length;
        const blockedWrongly = all.filter(evaluation => evaluation.unexpectedBlock).length;
        const result = gaps > 0
          ? `❗ ${gaps} gap${gaps === 1 ? "" : "s"}`
          : blockedWrongly > 0
            ? `⁉️ ${blockedWrongly} unexpected block${blockedWrongly === 1 ? "" : "s"}`
            : "✅";
        return [
          report.version,
          report.node,
          `${allowed}/${own_.length}${switched > 0 ? ` (+${switched} handed over)` : ""}`,
          freshIn.join(", ") || "none",
          result,
        ];
      }),
    ), "");

    add(
      "<details>",
      `<summary>${manager}: every setup${other.length > 0 && manifest.plan.crossManager ? ", including the other manager's" : ""}</summary>`,
      "",
      table(
        ["Version", ...own.map(setup => setup.id), ...(manifest.plan.crossManager ? other.map(setup => `${setup.id} (cross)`) : [])],
        managerReports.map(report => [
          report.version,
          ...own.map(setup => cell(find(report.version, setup))),
          ...(manifest.plan.crossManager ? other.map(setup => cell(find(report.version, setup))) : []),
        ]),
      ),
      "",
      "</details>",
      "",
    );
  }

  // Grouped findings.
  add("## Policy gaps", "");
  if (violations.length === 0) {
    add("None.", "");
  } else {
    const groups = new Map();
    for (const evaluation of violations) {
      for (const violation of evaluation.violations) {
        const key = `${evaluation.manager}|${evaluation.setup}|${violation.kind}`;
        if (!groups.has(key)) {
          groups.set(key, { evaluation, violation, entries: [] });
        }
        const detail = violation.kind === "disallowed-version" && violation.performers.some(performer => performer !== evaluation.version)
          ? `ran as ${violation.performers.join("/")}: ${violation.scenarios.map(short).join("")}`
          : violation.scenarios.map(short).join("");
        groups.get(key).entries.push({ version: evaluation.version, detail });
      }
    }
    // Setups with the same finding for the same versions share one line.
    const merged = new Map();
    for (const { evaluation, violation, entries } of groups.values()) {
      const versions = listVersions(entries);
      const key = `${evaluation.manager}|${violation.kind}|${evaluation.rule}|${versions}`;
      if (!merged.has(key)) {
        merged.set(key, { manager: evaluation.manager, kind: violation.kind, rule: evaluation.rule, versions, setups: [] });
      }
      merged.get(key).setups.push(evaluation.setup);
    }
    const setupOrder = id => setups.findIndex(setup => setup.id === id);
    const ordered = [...merged.values()].sort((left, right) =>
      left.manager.localeCompare(right.manager) ||
      KIND_ORDER.indexOf(left.kind) - KIND_ORDER.indexOf(right.kind) ||
      setupOrder(left.setups[0]) - setupOrder(right.setups[0]));
    for (const group of ordered) {
      add(`- **${group.manager}** in ${group.setups.map(id => `\`${id}\``).join(", ")} (intended: ${group.rule}): ${KIND_TEXT[group.kind]}: ${group.versions}`);
    }
    add("");
  }

  add("## Unexpected blocks", "");
  if (unexpected.length === 0) {
    add("None.", "");
  } else {
    const groups = new Map();
    for (const evaluation of unexpected) {
      const key = `${evaluation.manager}|${evaluation.setup}`;
      if (!groups.has(key)) {
        groups.set(key, { evaluation, entries: [] });
      }
      groups.get(key).entries.push({
        version: evaluation.version,
        detail: evaluation.state === "blocked" ? evaluation.blockedBy.join("/") : "failed",
      });
    }
    for (const { evaluation, entries } of groups.values()) {
      add(`- **${evaluation.manager}** on \`${evaluation.setup}\` (${evaluation.rule}): ${listVersions(entries)}`);
    }
    add("");
  }

  const storeOnly = evaluations.filter(evaluation => evaluation.freshStoreOnly.length > 0);
  if (storeOnly.length > 0) {
    add(
      "## Fresh versions extracted but not linked",
      "",
      "The command failed and the project cannot load these, but the files were downloaded into node_modules/.pnpm.",
      "",
    );
    const groups = new Map();
    for (const evaluation of storeOnly) {
      const key = `${evaluation.manager}|${evaluation.setup}`;
      if (!groups.has(key)) {
        groups.set(key, { evaluation, entries: [] });
      }
      groups.get(key).entries.push({ version: evaluation.version, detail: evaluation.freshStoreOnly.map(short).join("") });
    }
    for (const { evaluation, entries } of groups.values()) {
      add(`- **${evaluation.manager}** on \`${evaluation.setup}\`: ${listVersions(entries)}`);
    }
    add("");
  }

  if (installErrors.length > 0) {
    add("## Versions that could not run", "");
    for (const report of installErrors) {
      add(`- ${report.manager}@${report.version} on Node.js ${report.node}: ${escapeMarkdown(report.installError.split("\n").slice(0, 3).join(" "))}`);
    }
    add("");
  }

  add(
    "## Files",
    "",
    "The `package-manager-test-report` artifact has this report, `results.csv` with every command (exit code, error code, versions on disk, which version ran), and `summary.json`. Each `pm-*` artifact has the full log of every command for one version.",
    "",
  );

  const markdown = `${lines.join("\n")}\n`;
  fs.writeFileSync(path.join(out, "report.md"), markdown);

  const csvColumns = [
    "manager", "version", "node", "setup", "setupManager", "scenario", "command", "cwd", "ci",
    "exitCode", "outcome", "errorCode", "resolved", "versionsOnDisk", "freshVersions", "fresh",
    "ran", "performer", "performerSource", "durationMs", "log",
  ];
  const csv = [csvColumns.join(",")];
  for (const report of reports) {
    for (const row of report.results) {
      csv.push(csvColumns.map(column =>
        csvValue(column in row ? row[column] : report[column])).join(","));
    }
  }
  fs.writeFileSync(path.join(out, "results.csv"), `${csv.join("\n")}\n`);

  writeJson(path.join(out, "summary.json"), {
    manifest: { ...manifest, package: { ...manifest.package, times: undefined } },
    policy,
    missing,
    evaluations,
  });

  if (process.env.GITHUB_STEP_SUMMARY) {
    const summary = Buffer.byteLength(markdown) <= SUMMARY_LIMIT
      ? markdown
      : `${markdown.slice(0, SUMMARY_LIMIT)}\n\n…truncated; download the package-manager-test-report artifact for the full report.\n`;
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
  }
  console.log(markdown);

  const failures = [
    ...(failOnViolation && violations.length > 0 ? [`${violations.length} policy gaps`] : []),
    ...(rejected.length > 0 ? [`${rejected.length} setups rejected by the policy`] : []),
    ...(args["require-policy"] === "true" && unchecked.length > 0 ? [`${unchecked.length} setups without a policy check`] : []),
    ...(missing.length > 0 ? [`${missing.length} versions without results`] : []),
  ];
  if (failures.length > 0) {
    console.log(`::error::${failures.join("; ")}`);
    process.exit(1);
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
}
