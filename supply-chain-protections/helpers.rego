package supply_chain.policies

import rego.v1

inline_install_with_package_pattern := concat("", [
    `(?im)(^|[;&|]\s*|\s)(npm|pnpm|yarn|bun|deno)(\.cmd)?`,
    `\s+(i|install)(\s+--?[a-z0-9-]+(=[^\s]+)?)*`,
    `\s+(@?[a-z0-9_./])`,
])

policy_finding(message, file, policy_id) := {
    "msg": message,
    "_loc": {
        "file": file,
        "line": 1,
    },
    "policy_id": policy_id,
}

# approved_write(path, job, scope) if {
#     scope in data.supply_chain.approved_writes[path][job]
# }

tracked(path) if {
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

lockfile_path(project) := path_for(project.root, "package-lock.json") if {
    project.manager == "npm"
}

lockfile_path(project) := path_for(project.root, "pnpm-lock.yaml") if {
    project.manager == "pnpm"
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

valid_github_pin(reference) if {
    regex.match(
        `^[^/@\s]+/[^@\s]+(?:/[^@\s]+)*@[0-9a-fA-F]{40}$`,
        reference,
    )
}

valid_docker_pin(reference) if {
    regex.match(
        `^docker://[^@\s]+@sha256:[0-9a-f]{64}$`,
        reference,
    )
}

github_pin_exception(reference) if {
    reference in {
        "bcc-code/bcc-platform-deploy/.github/workflows/landing-zone.yml@main",
        "bcc-code/bcc-platform-deploy/.github/workflows/terraform.yml@main",
    }
}

engine_at_least(constraint, minimum) if {
    is_string(constraint)
    clauses := regex.split(`\s*\|\|\s*`, trim_space(constraint))
    count(clauses) > 0
    every clause in clauses {
        range_clause_at_least(clause, minimum)
    }
}

range_clause_at_least(clause, minimum) if {
    regex.match(`\s+-\s+`, clause)
    version_token := regex.find_n(
        `[0-9]+(?:\.(?:[0-9]+|[xX*])){0,2}`,
        clause,
        1,
    )[0]
    version := normalized_semver(version_token)
    semver.compare(version, minimum) >= 0
}

range_clause_at_least(clause, minimum) if {
    not regex.match(`\s+-\s+`, clause)
    without_upper_bounds := regex.replace(
        clause,
        `<=?\s*v?[0-9]+(?:\.(?:[0-9]+|[xX*])){0,2}`,
        "",
    )
    some version_token in regex.find_n(
        `[0-9]+(?:\.(?:[0-9]+|[xX*])){0,2}`,
        without_upper_bounds,
        -1,
    )
    version := normalized_semver(version_token)
    semver.compare(version, minimum) >= 0
}

normalized_semver(version) := version if {
    regex.match(`^[0-9]+\.[0-9]+\.[0-9]+$`, version)
}

normalized_semver(version) := sprintf("%s.0", [version]) if {
    regex.match(`^[0-9]+\.[0-9]+$`, version)
}

normalized_semver(version) := sprintf("%s.0.0", [major]) if {
    regex.match(`^[0-9]+\.(?:[xX*])$`, version)
    major := regex.split(`\.`, version)[0]
}

normalized_semver(version) := sprintf("%s.0.0", [version]) if {
    regex.match(`^[0-9]+$`, version)
}

normalized_semver(version) := normalized if {
    regex.match(`^[0-9]+\.(?:[0-9]+|[xX*])\.(?:[0-9]+|[xX*])$`, version)
    normalized := concat(".", [
        wildcard_to_zero(regex.split(`\.`, version)[0]),
        wildcard_to_zero(regex.split(`\.`, version)[1]),
        wildcard_to_zero(regex.split(`\.`, version)[2]),
    ])
}

wildcard_to_zero(part) := "0" if {
    part in {"x", "X", "*"}
}

wildcard_to_zero(part) := part if {
    not part in {"x", "X", "*"}
}

true_value(value) if {
    value == true
}

true_value(value) if {
    lower(sprintf("%v", [value])) == "true"
}

number_at_least(value, minimum) if {
    is_number(value)
    value >= minimum
}

number_at_least(value, minimum) if {
    is_string(value)
    regex.match(`^[0-9]+([.][0-9]+)?$`, value)
    to_number(value) >= minimum
}

npm_install(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)npm(\.cmd)?\s+(i|install)(\s|$)`,
        command,
    )
}

uses_npm(command) if {
    regex.match(`(?im)(^|[;&|]\s*|\s)(npm|npx)(\.cmd)?\s+`, command)
}

uses_inline_install(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)(npx(\.cmd)?|pnpx(\.cmd)?|bunx)(\s|$)`,
        command,
    )
}

uses_inline_install(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)(bun(\.cmd)?\s+x|npm(\.cmd)?\s+(exec|x))(\s|$)`,
        command,
    )
}

uses_inline_install(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)(pnpm|yarn)(\.cmd)?\s+dlx(\s|$)`,
        command,
    )
}

uses_inline_install(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)(npm|pnpm|yarn|bun|deno)(\.cmd)?\s+add(\s|$)`,
        command,
    )
}

uses_inline_install(command) if {
    regex.match(inline_install_with_package_pattern, command)
}

uses_inline_install(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)(npm|pnpm|yarn|bun)(\.cmd)?\s+(global|g)\s+add(\s|$)`,
        command,
    )
}

uses_forbidden_manager(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)(yarn|bun|deno)\s+(install|add|run|exec|x)(\s|$)`,
        command,
    )
}

forbidden_lockfile(path) if {
    regex.match(`(^|/)yarn\.lock$`, path)
}

forbidden_lockfile(path) if {
    regex.match(`(^|/)(bun\.lockb?|deno\.lock)$`, path)
}