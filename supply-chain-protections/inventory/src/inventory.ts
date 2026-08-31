import dockerIgnore, { type Ignore } from "@balena/dockerignore";
import { DockerfileParser } from "dockerfile-ast";
import { parse as parseIni } from "ini";
import fs from "node:fs/promises";
import path from "node:path";
import { parseDocument } from "yaml";

type JsonObject = Record<string, unknown>;
type DockerIgnoreFactory = (
  options?: {
    ignorecase?: boolean;
  },
) => Ignore;

interface Project {
  root: string;
  manager: string;
  packagePath: string;
  package: JsonObject;
  npmrcPath: string;
  npmrc: JsonObject;
  workspacePath: string;
  workspace: JsonObject;
  lockfilePath: string;
}

interface GitHubDocument {
  path: string;
  document: JsonObject;
}

interface CiCommand {
  path: string;
  projectRoot: string;
  command: string;
  env: JsonObject;
}

interface ContainerBuild {
  path: string;
  projectRoot: string;
  copiedFiles: string[];
}

export interface Inventory {
  schemaVersion: 1;
  repository: string;
  trackedFiles: string[];
  projects: Project[];
  githubDocuments: GitHubDocument[];
  ciCommands: CiCommand[];
  containerBuilds: ContainerBuild[];
}

const excludedDirectories = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
]);

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function relativePath(directory: string, name: string): string {
  return directory === "." ? name : `${directory}/${name}`;
}

function parentDirectory(directory: string): string {
  if (directory === ".") {
    return ".";
  }

  const parent = path.posix.dirname(directory);
  return parent === "" ? "." : parent;
}

async function collectFiles(
  root: string,
  directory = ".",
): Promise<string[]> {
  const absoluteDirectory =
    directory === "." ? root : path.join(root, ...directory.split("/"));

  const entries = await fs.readdir(absoluteDirectory, {
    withFileTypes: true,
  });

  const files: string[] = [];

  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      continue;
    }

    const file = relativePath(directory, entry.name);

    if (entry.isDirectory()) {
      if (!excludedDirectories.has(entry.name)) {
        files.push(...await collectFiles(root, file));
      }
      continue;
    }

    if (entry.isFile()) {
      files.push(file);
    }
  }

  return files.sort();
}

function absolutePath(root: string, file: string): string {
  return path.join(root, ...file.split("/"));
}

async function readText(root: string, file: string): Promise<string> {
  return fs.readFile(absolutePath(root, file), "utf8");
}

async function readJson(root: string, file: string): Promise<JsonObject> {
  const value: unknown = JSON.parse(await readText(root, file));

  if (!isObject(value)) {
    throw new Error(`${file} must contain a JSON object`);
  }

  return value;
}

async function readYaml(root: string, file: string): Promise<JsonObject> {
  const parsed = parseDocument(await readText(root, file), {
    version: "1.2",
    merge: true,
  });

  if (parsed.errors.length > 0) {
    throw new Error(`${file}: ${parsed.errors[0].message}`);
  }

  const value: unknown = parsed.toJS({ maxAliasCount: 100 });

  if (!isObject(value)) {
    throw new Error(`${file} must contain a YAML mapping`);
  }

  return value;
}

async function readIni(root: string, file: string): Promise<JsonObject> {
  const value: unknown = parseIni(await readText(root, file));
  return isObject(value) ? value : {};
}

function closestFile(
  directory: string,
  files: Set<string>,
  names: readonly string[],
): string {
  let current = directory;

  while (true) {
    for (const name of names) {
      const candidate = relativePath(current, name);
      if (files.has(candidate)) {
        return candidate;
      }
    }

    if (current === ".") {
      return "";
    }

    current = parentDirectory(current);
  }
}

function declaredManager(packageDocument: JsonObject): string {
  const value = packageDocument.packageManager;

  if (typeof value !== "string") {
    return "";
  }

  const separator = value.indexOf("@");
  return separator > 0 ? value.slice(0, separator) : value;
}

function detectManager(
  directory: string,
  packageDocument: JsonObject,
  files: Set<string>,
): string {
  const declared = declaredManager(packageDocument);
  if (declared !== "") {
    return declared;
  }

  if (closestFile(directory, files, ["pnpm-workspace.yaml"]) !== "") {
    return "pnpm";
  }

  if (closestFile(directory, files, ["pnpm-lock.yaml"]) !== "") {
    return "pnpm";
  }

  if (closestFile(directory, files, ["package-lock.json"]) !== "") {
    return "npm";
  }

  if (closestFile(directory, files, ["yarn.lock"]) !== "") {
    return "yarn";
  }

  if (closestFile(directory, files, ["bun.lock", "bun.lockb"]) !== "") {
    return "bun";
  }

  if (closestFile(directory, files, ["deno.lock"]) !== "") {
    return "deno";
  }

  return "unknown";
}

async function discoverProjects(
  root: string,
  trackedFiles: string[],
): Promise<Project[]> {
  const files = new Set(trackedFiles);
  const projects: Project[] = [];

  for (const packagePath of trackedFiles.filter(
    file => path.posix.basename(file) === "package.json",
  )) {
    const projectRoot = parentDirectory(packagePath);
    const packageDocument = await readJson(root, packagePath);
    const manager = detectManager(projectRoot, packageDocument, files);

    const npmrcPath = closestFile(projectRoot, files, [".npmrc"]);
    const workspacePath = closestFile(
      projectRoot,
      files,
      ["pnpm-workspace.yaml"],
    );

    const lockfilePath = closestFile(
      projectRoot,
      files,
      manager === "pnpm"
        ? ["pnpm-lock.yaml"]
        : manager === "npm"
          ? ["package-lock.json"]
          : ["pnpm-lock.yaml", "package-lock.json"],
    );

    projects.push({
      root: projectRoot,
      manager,
      packagePath,
      package: packageDocument,
      npmrcPath,
      npmrc: npmrcPath === "" ? {} : await readIni(root, npmrcPath),
      workspacePath,
      workspace:
        workspacePath === "" ? {} : await readYaml(root, workspacePath),
      lockfilePath,
    });
  }

  return projects;
}

function isWorkflow(file: string): boolean {
  if (!file.startsWith(".github/workflows/")) {
    return false;
  }

  const nestedPath = file.slice(".github/workflows/".length);
  return !nestedPath.includes("/") && /\.ya?ml$/i.test(file);
}

function isAction(file: string): boolean {
  return /^action\.ya?ml$/i.test(path.posix.basename(file));
}

async function discoverGitHubDocuments(
  root: string,
  trackedFiles: string[],
): Promise<GitHubDocument[]> {
  const documents: GitHubDocument[] = [];

  for (const file of trackedFiles.filter(
    candidate => isWorkflow(candidate) || isAction(candidate),
  )) {
    documents.push({
      path: file,
      document: await readYaml(root, file),
    });
  }

  return documents;
}

function mergeEnvironment(...values: unknown[]): JsonObject {
  const result: JsonObject = {};

  for (const value of values) {
    if (isObject(value)) {
      Object.assign(result, value);
    }
  }

  return result;
}

function workingDirectory(...values: unknown[]): string {
  const selected = [...values].reverse().find(
    value => typeof value === "string" && value !== "",
  );

  if (typeof selected !== "string" || selected.includes("${{")) {
    return ".";
  }

  const normalized = path.posix.normalize(
    selected.replaceAll("\\", "/").replace(/^\/+/, ""),
  );

  return normalized === "" || normalized.startsWith("..")
    ? "."
    : normalized;
}

function defaultWorkingDirectory(value: unknown): unknown {
  if (!isObject(value) || !isObject(value.defaults)) {
    return undefined;
  }

  const run = value.defaults.run;
  return isObject(run) ? run["working-directory"] : undefined;
}

function projectForDirectory(
  directory: string,
  projects: Project[],
): string {
  const matches = projects
    .map(project => project.root)
    .filter(root =>
      root === "." ||
      directory === root ||
      directory.startsWith(`${root}/`)
    )
    .sort((left, right) => right.length - left.length);

  return matches[0] ?? ".";
}

function extractDocumentCommands(
  document: GitHubDocument,
  projects: Project[],
): CiCommand[] {
  const commands: CiCommand[] = [];
  const content = document.document;
  const workflowEnvironment = content.env;
  const workflowDirectory = defaultWorkingDirectory(content);

  if (isObject(content.jobs)) {
    for (const job of Object.values(content.jobs)) {
      if (!isObject(job) || !Array.isArray(job.steps)) {
        continue;
      }

      for (const step of job.steps) {
        if (!isObject(step) || typeof step.run !== "string") {
          continue;
        }

        const directory = workingDirectory(
          workflowDirectory,
          defaultWorkingDirectory(job),
          step["working-directory"],
        );

        commands.push({
          path: document.path,
          projectRoot: projectForDirectory(directory, projects),
          command: step.run,
          env: mergeEnvironment(
            workflowEnvironment,
            job.env,
            step.env,
          ),
        });
      }
    }
  }

  if (isObject(content.runs) && Array.isArray(content.runs.steps)) {
    for (const step of content.runs.steps) {
      if (!isObject(step) || typeof step.run !== "string") {
        continue;
      }

      const directory = workingDirectory(step["working-directory"]);

      commands.push({
        path: document.path,
        projectRoot: projectForDirectory(directory, projects),
        command: step.run,
        env: mergeEnvironment(step.env),
      });
    }
  }

  return commands;
}

function isDockerfile(file: string): boolean {
  const name = path.posix.basename(file);
  return name === "Dockerfile" ||
    name.startsWith("Dockerfile.") ||
    name.endsWith(".Dockerfile");
}

function repositoryPath(contextRoot: string, localFile: string): string {
  return contextRoot === "."
    ? localFile
    : `${contextRoot}/${localFile}`;
}

function filesInContext(
  contextRoot: string,
  trackedFiles: string[],
): string[] {
  if (contextRoot === ".") {
    return trackedFiles;
  }

  const prefix = `${contextRoot}/`;

  return trackedFiles
    .filter(file => file.startsWith(prefix))
    .map(file => file.slice(prefix.length));
}

async function dockerIgnoreFilter(
  root: string,
  contextRoot: string,
  trackedFiles: string[],
): Promise<string[]> {
  const files = filesInContext(contextRoot, trackedFiles);
  const ignorePath = relativePath(contextRoot, ".dockerignore");

  if (!trackedFiles.includes(ignorePath)) {
    return files;
  }

  const createDockerIgnore =
    dockerIgnore as unknown as DockerIgnoreFactory;
  const matcher = createDockerIgnore({ ignorecase: false })
    .add(await readText(root, ignorePath));

  return files.filter(file => !matcher.ignores(file));
}

function normalizeCopySource(source: string): string {
  return source
    .replaceAll("\\", "/")
    .replace(/^\/+/, "")
    .replace(/^(\.\.\/)+/, "")
    .replace(/^\.\//, "")
    .replace(/\/+$/, "");
}

function sourceMatches(file: string, source: string): boolean {
  if (source === "" || source === ".") {
    return true;
  }

  return file === source ||
    file.startsWith(`${source}/`) ||
    path.matchesGlob(file, source);
}

function inlineEnvironment(command: string): JsonObject {
  const environment: JsonObject = {};
  const match = command.match(
    /(?:^|[;&|]\s*)CI=(?:"([^"]*)"|'([^']*)'|([^\s;&|]+))/i,
  );

  if (match) {
    environment.CI = match[1] ?? match[2] ?? match[3];
  }

  return environment;
}

async function inspectDockerfiles(
  root: string,
  trackedFiles: string[],
  projects: Project[],
): Promise<{
  builds: ContainerBuild[];
  commands: CiCommand[];
}> {
  const builds: ContainerBuild[] = [];
  const commands: CiCommand[] = [];

  for (const file of trackedFiles.filter(isDockerfile)) {
    const projectRoot = projectForDirectory(
      parentDirectory(file),
      projects,
    );

    const contextFiles = await dockerIgnoreFilter(
      root,
      projectRoot,
      trackedFiles,
    );

    const dockerfile = DockerfileParser.parse(await readText(root, file));
    const copiedFiles = new Set<string>();

    for (const copy of dockerfile.getCOPYs()) {
      if (copy.getFromFlag() !== null) {
        continue;
      }

      const argumentsList = copy.getArguments().map(
        argument => argument.getValue(),
      );

      for (const rawSource of argumentsList.slice(0, -1)) {
        if (rawSource.startsWith("<<")) {
          continue;
        }

        const source = normalizeCopySource(rawSource);

        for (const contextFile of contextFiles) {
          if (sourceMatches(contextFile, source)) {
            copiedFiles.add(repositoryPath(projectRoot, contextFile));
          }
        }
      }
    }

    for (const instruction of dockerfile.getInstructions()) {
      if (instruction.getKeyword() !== "RUN") {
        continue;
      }

      const command = instruction.getArgumentsContent() ?? "";
      const line = instruction.getRange().start.line;
      const environment = inlineEnvironment(command);
      const ci = dockerfile.resolveVariable("CI", line);

      if (ci !== undefined && ci !== null) {
        environment.CI = ci;
      }

      commands.push({
        path: file,
        projectRoot,
        command,
        env: environment,
      });
    }

    builds.push({
      path: file,
      projectRoot,
      copiedFiles: [...copiedFiles].sort(),
    });
  }

  return { builds, commands };
}

export async function generateInventory(
  rootInput: string,
  repository: string,
): Promise<Inventory> {
  const root = path.resolve(rootInput);
  const trackedFiles = await collectFiles(root);
  const projects = await discoverProjects(root, trackedFiles);
  const githubDocuments = await discoverGitHubDocuments(
    root,
    trackedFiles,
  );

  const githubCommands = githubDocuments.flatMap(
    document => extractDocumentCommands(document, projects),
  );

  const docker = await inspectDockerfiles(
    root,
    trackedFiles,
    projects,
  );

  return {
    schemaVersion: 1,
    repository,
    trackedFiles,
    projects,
    githubDocuments,
    ciCommands: [...githubCommands, ...docker.commands],
    containerBuilds: docker.builds,
  };
}