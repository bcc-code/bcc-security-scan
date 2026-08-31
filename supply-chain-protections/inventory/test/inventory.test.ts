import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { generateInventory } from "../src/inventory.ts";

async function write(
  root: string,
  file: string,
  content: string,
): Promise<void> {
  const destination = path.join(root, ...file.split("/"));
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.writeFile(destination, content);
}

test("generates policy inventory", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "supply-chain-inventory-"),
  );

  try {
    await write(root, "package.json", JSON.stringify({
      packageManager: "pnpm@11.24.0",
      engines: {
        npm: "disallow",
        pnpm: ">=11.0.0",
      },
      scripts: {
        test: "pnpm test",
      },
    }));

    await write(root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");

    await write(root, "pnpm-workspace.yaml", [
      "packages: []",
      "engineStrict: true",
      "minimumReleaseAge: 10080",
      "minimumReleaseAgeStrict: true",
      "blockExoticSubdeps: true",
      "strictDepBuilds: true",
      "pmOnFail: error",
      "dangerouslyAllowAllBuilds: false",
      "",
    ].join("\n"));

    await write(root, ".github/workflows/ci.yml", [
      "on: push",
      "env:",
      "  CI: true",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-24.04",
      "    steps:",
      "      - uses: actions/checkout@v7",
      "      - run: pnpm install --frozen-lockfile",
      "",
    ].join("\n"));

    await write(root, "Dockerfile", [
      "FROM node:24",
      "ENV CI=true",
      "COPY package.json pnpm-lock.yaml ./",
      "RUN pnpm install --frozen-lockfile",
      "",
    ].join("\n"));

    const inventory = await generateInventory(
      root,
      "bcc-code/example",
    );

    assert.equal(inventory.repository, "bcc-code/example");
    assert.equal(inventory.projects.length, 1);
    assert.equal(inventory.projects[0].manager, "pnpm");
    assert.equal(inventory.githubDocuments.length, 1);
    assert.equal(inventory.ciCommands.length, 2);
    assert.equal(inventory.containerBuilds.length, 1);

    assert.deepEqual(
      inventory.containerBuilds[0].copiedFiles,
      ["package.json", "pnpm-lock.yaml"],
    );

    assert.equal(inventory.ciCommands[0].env.CI, true);
    assert.equal(inventory.ciCommands[1].env.CI, "true");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});