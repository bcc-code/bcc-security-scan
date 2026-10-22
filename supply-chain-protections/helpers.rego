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

# ---------------------------------------------------------------------------
# GitHub Actions references
# ---------------------------------------------------------------------------

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

# Infra Platform reusable workflows are trusted to track their main branch.
is_pin_exception(reference) if {
    reference in {
        "bcc-code/bcc-platform-deploy/.github/workflows/landing-zone.yml@main",
        "bcc-code/bcc-platform-deploy/.github/workflows/terraform.yml@main",
    }
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

# Splits an exact packageManager pin (`name@x.y.z`, optionally `+sha512.<hex>`)
# into its name, version, and hash. Ranges and partial versions do not match.
package_manager_pin(package_document) := {"name": match[1], "version": match[2], "hash": match[3]} if {
    value := object.get(package_document, "packageManager", "")
    is_string(value)
    match := regex.find_all_string_submatch_n(
        `^([a-z]+)@([0-9]+\.[0-9]+\.[0-9]+)(?:\+(sha[0-9]+\.[0-9a-f]+))?$`,
        value,
        1,
    )[0]
}

# packageManager must pin an exact version, which Corepack and pnpm use to run that exact release.
package_manager_pinned_at_least(package_document, manager, minimum) if {
    pin := package_manager_pin(package_document)
    pin.name == manager
    semver.compare(pin.version, minimum) >= 0
}

# Also requires a SHA-512 hash of the release, as written by `corepack use`,
# which Corepack checks before running the release.
package_manager_hash_pinned_at_least(package_document, manager, minimum) if {
    package_manager_pinned_at_least(package_document, manager, minimum)
    regex.match(`^sha512\.[0-9a-f]{128}$`, package_manager_pin(package_document).hash)
}

# Older pnpm versions ignore the packageManager version but refuse to run
# when engines.pnpm excludes them, so both are needed to prove the version.
pnpm_version_proven(package_document, minimum) if {
    package_manager_pinned_at_least(package_document, "pnpm", minimum)
    engines := object.get(package_document, "engines", {})
    engine_at_least(object.get(engines, "pnpm", ""), minimum)
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
