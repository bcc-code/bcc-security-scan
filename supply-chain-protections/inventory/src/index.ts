import core from "@actions/core";

async function run() {
  const root = core.getInput("root", { required: true });
  const output = core.getInput("output", { required: true });
  const repository = core.getInput("repository", { required: true });

  const inventory = await generateInventory(root, repository);
  await fs.writeFile(output, JSON.stringify(inventory, null, 2));

  core.setOutput("inventory", output);
}

run().catch(error => core.setFailed(error.message));
