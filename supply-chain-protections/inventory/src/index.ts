import * as core from "@actions/core";
import fs from "node:fs/promises";
import path from "node:path";
import { generateInventory } from "./inventory.js";

async function run(): Promise<void> {
  const root = core.getInput("root", { required: true });
  const output = core.getInput("output", { required: true });
  const repository = core.getInput("repository", { required: true });

  const inventory = await generateInventory(root, repository);

  await fs.mkdir(path.dirname(output), { recursive: true });
  await fs.writeFile(output, JSON.stringify(inventory, null, 2));

  core.setOutput("inventory", output);
}

run().catch((error: unknown) => {
  core.setFailed(error instanceof Error ? error.message : String(error));
});
