package supply_chain.policies

import rego.v1

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

# Builds a finding in the shape Conftest reports as SARIF.
# The inventory does not record line numbers, so findings point at line 1.
policy_finding(message, file, policy_id) := {
	"msg": message,
	"_loc": {
		"file": file,
		"line": 1,
	},
	"policy_id": policy_id,
}

# ---------------------------------------------------------------------------
# Inventory lookups
# ---------------------------------------------------------------------------

is_tracked(path) if {
	path in input.trackedFiles
}

project_for(root) := project if {
	some project in input.projects
	project.root == root
}

path_for(root, name) := name if {
	root == "."
}

path_for(root, name) := sprintf("%s/%s", [trim(root, "/"), name]) if {
	root != "."
}

directory_of(path) := "." if {
	not contains(path, "/")
}

directory_of(path) := regex.replace(path, `/[^/]+$`, "") if {
	contains(path, "/")
}

# pnpm reads packageManager and devEngines.packageManager only from the
# package.json next to pnpm-workspace.yaml, not from workspace sub-packages.
workspace_package_path(project) := path_for(directory_of(project.workspacePath), "package.json")

workspace_package(project) := root.package if {
	root := project_for(directory_of(project.workspacePath))
}

workspace_package(project) := {} if {
	not project_for(directory_of(project.workspacePath))
}

# True for the package.json next to pnpm-workspace.yaml, and for projects without one.
is_workspace_root(project) if {
	project.workspacePath == ""
}

is_workspace_root(project) if {
	project.root == directory_of(project.workspacePath)
}

in_pnpm_project(command) if {
	project_for(command.projectRoot).manager == "pnpm"
}

# ---------------------------------------------------------------------------
# GitHub Actions references
# ---------------------------------------------------------------------------

github_document_paths := {document.path | some document in input.githubDocuments}

# Every `uses:` value in a workflow or action document,
# covering steps, reusable workflow jobs, and composite actions.
action_references(document) := {reference |
	some _, node in walk(document)
	is_object(node)
	reference := object.get(node, "uses", "")
	reference != ""
}

is_local_reference(reference) if {
	startswith(reference, "./")
}

is_local_reference(reference) if {
	startswith(reference, "$/")
}

is_docker_reference(reference) if {
	startswith(reference, "docker://")
}

is_commit_sha_pin(reference) if {
	regex.match(`^[^/@\s]+/[^@\s]+(?:/[^@\s]+)*@[0-9a-fA-F]{40}$`, reference)
}

is_image_digest_pin(reference) if {
	regex.match(`^docker://[^@\s]+@sha256:[0-9a-f]{64}$`, reference)
}

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

# A semver range is at least `minimum` when every `||` alternative
# has a lower bound of at least `minimum`.
engine_at_least(constraint, minimum) if {
	is_string(constraint)
	clauses := regex.split(`\s*\|\|\s*`, trim_space(constraint))
	count(clauses) > 0
	every clause in clauses {
		range_clause_at_least(clause, minimum)
	}
}

# Hyphen ranges (`1.2.3 - 2.0.0`): the first version is the lower bound.
range_clause_at_least(clause, minimum) if {
	regex.match(`\s+-\s+`, clause)
	version := normalized_semver(version_tokens(clause)[0])
	semver.compare(version, minimum) >= 0
}

# Other ranges: after removing upper bounds, some remaining version
# must be at least `minimum`.
range_clause_at_least(clause, minimum) if {
	not regex.match(`\s+-\s+`, clause)
	lower_bounds := regex.replace(clause, `<=?\s*v?[0-9]+(?:\.(?:[0-9]+|[xX*])){0,2}`, "")
	some token in version_tokens(lower_bounds)
	semver.compare(normalized_semver(token), minimum) >= 0
}

version_tokens(text) := regex.find_n(`[0-9]+(?:\.(?:[0-9]+|[xX*])){0,2}`, text, -1)

# Expands partial and wildcard versions (`11`, `11.2`, `11.x`, `11.2.*`) to `major.minor.patch`.
normalized_semver(version) := version if {
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+$`, version)
}

normalized_semver(version) := sprintf("%s.0", [version]) if {
	regex.match(`^[0-9]+\.[0-9]+$`, version)
}

normalized_semver(version) := sprintf("%s.0.0", [major]) if {
	regex.match(`^[0-9]+\.(?:[xX*])$`, version)
	major := split(version, ".")[0]
}

normalized_semver(version) := sprintf("%s.0.0", [version]) if {
	regex.match(`^[0-9]+$`, version)
}

normalized_semver(version) := concat(".", [wildcard_to_zero(part) | some part in split(version, ".")]) if {
	regex.match(`^[0-9]+\.(?:[0-9]+|[xX*])\.(?:[0-9]+|[xX*])$`, version)
}

wildcard_to_zero(part) := "0" if {
	part in {"x", "X", "*"}
}

wildcard_to_zero(part) := part if {
	not part in {"x", "X", "*"}
}

# devEngines.packageManager must name an exact version. pnpm records that release's
# integrity in pnpm-lock.yaml and refuses to run a release that does not match it.
# A range would switch to whichever matching release is newest.
dev_engines_pinned_at_least(package_document, manager, minimum) if {
	dev_engines := object.get(package_document, "devEngines", {})
	package_manager := object.get(dev_engines, "packageManager", {})
	is_object(package_manager)
	is_exact_pin(package_manager, manager, minimum)
}

is_exact_pin(entry, manager, minimum) if {
	object.get(entry, "name", "") == manager
	version := object.get(entry, "version", "")
	is_string(version)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+$`, version)
	semver.compare(version, minimum) >= 0
}

# devEngines.packageManager may be one entry or a list of entries.
dev_engines_package_managers(package_document) := [package_manager] if {
	package_manager := object.get(object.get(package_document, "devEngines", {}), "packageManager", null)
	is_object(package_manager)
}

dev_engines_package_managers(package_document) := package_managers if {
	package_managers := object.get(object.get(package_document, "devEngines", {}), "packageManager", null)
	is_array(package_managers)
}

# ---------------------------------------------------------------------------
# Config values
# ---------------------------------------------------------------------------

# YAML and .npmrc values may be booleans or strings.
is_true(value) if {
	lower(sprintf("%v", [value])) == "true"
}

# YAML and .npmrc values may be numbers or numeric strings.
number_at_least(value, minimum) if {
	is_number(value)
	value >= minimum
}

number_at_least(value, minimum) if {
	is_string(value)
	regex.match(`^[0-9]+([.][0-9]+)?$`, value)
	to_number(value) >= minimum
}

# ---------------------------------------------------------------------------
# Shell commands
# ---------------------------------------------------------------------------

# A CI or container command as the CI rules check it.
# Container builds may install pnpm globally with an exact, allowed version
# (`npm install -g pnpm@x.y.z`), because that is how images get pnpm.
# Those installs are removed first; the rest of the command is still checked.
checked_command(command) := strings.replace_n(
	{install.text: install.replacement | some install in allowed_pnpm_global_installs(command.command)},
	command.command,
) if {
	command.path in container_build_paths
}

checked_command(command) := command.command if {
	not command.path in container_build_paths
}

container_build_paths := {build.path | some build in input.containerBuilds}

# `npm install -g pnpm@x.y.z` (also `npm i`, `--global`, or the flag after the package)
# with nothing else installed by the same npm command.
pnpm_global_install_pattern := concat("", [
	`(?im)npm(?:\.cmd)?[ \t]+(?:i|install)[ \t]+`,
	`(?:(?:-g|--global)[ \t]+pnpm@([0-9]+\.[0-9]+\.[0-9]+)|pnpm@([0-9]+\.[0-9]+\.[0-9]+)[ \t]+(?:-g|--global))`,
	`[ \t]*(?:$|([;&|]))`,
])

# Each allowed install's text, and what replaces it: the shell operator that ended it, if any.
allowed_pnpm_global_installs(command) := {{"text": match[0], "replacement": sprintf(" %s", [match[3]])} |
	some match in regex.find_all_string_submatch_n(pnpm_global_install_pattern, command, -1)
	version := concat("", [match[1], match[2]])
	semver.compare(version, "11.0.0") >= 0
}

# Matches `pattern` where a command starts: at the beginning of a line,
# after a shell operator (`;`, `&`, `|`), or after whitespace.
runs(command, pattern) if {
	regex.match(concat("", [`(?im)(^|[;&|]\s*|\s)`, pattern]), command)
}

runs_pnpm(command) if {
	runs(command, `pnpm(\.cmd)?(\s|$)`)
}

runs_npm(command) if {
	runs(command, `(npm|npx)(\.cmd)?\s+`)
}

runs_npm_install(command) if {
	runs(command, `npm(\.cmd)?\s+(i|install)(\s|$)`)
}

runs_unsupported_manager(command) if {
	runs(command, `(yarn|bun|deno)\s+(install|add|run|exec|x)(\s|$)`)
}

# Commands that download and run a package, or add one outside the lockfile.
runs_inline_package(command) if {
	some pattern in inline_package_patterns
	runs(command, pattern)
}

inline_package_patterns := {
	# Package runners: npx, pnpx, bunx.
	`(npx(\.cmd)?|pnpx(\.cmd)?|bunx)(\s|$)`,
	# Runner subcommands: bun x, npm exec, npm x.
	`(bun(\.cmd)?\s+x|npm(\.cmd)?\s+(exec|x))(\s|$)`,
	# Runner subcommands: pnpm dlx, yarn dlx.
	`(pnpm|yarn)(\.cmd)?\s+dlx(\s|$)`,
	# Adding a dependency: `<manager> add`.
	`(npm|pnpm|yarn|bun|deno)(\.cmd)?\s+add(\s|$)`,
	# Installing a named package: `<manager> install [flags] <package>`.
	concat("", [
		`(npm|pnpm|yarn|bun|deno)(\.cmd)?`,
		`\s+(i|install)(\s+--?[a-z0-9-]+(=[^\s]+)?)*`,
		`\s+(@?[a-z0-9_./])`,
	]),
	# Adding a global dependency: `<manager> global add`.
	`(npm|pnpm|yarn|bun)(\.cmd)?\s+(global|g)\s+add(\s|$)`,
}

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

is_unsupported_lockfile(path) if {
	regex.match(`(^|/)(yarn\.lock|bun\.lockb?|deno\.lock)$`, path)
}
