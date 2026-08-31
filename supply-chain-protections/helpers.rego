package supply_chain.policies

import rego.v1

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

engine_at_least(constraint, minimum) if {
    regex.match(`^\s*>=\s*[0-9]+\.[0-9]+\.[0-9]+`, constraint)
    version := regex.find_n(`[0-9]+\.[0-9]+\.[0-9]+`, constraint, 1)[0]
    semver.compare(version, minimum) >= 0
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
    regex.match(`(?im)(^|[;&|]\s*|\s)npm(\.cmd)?\s+`, command)
}

uses_forbidden_manager(command) if {
    regex.match(
        `(?im)(^|[;&|]\s*|\s)(yarn|bun|deno)\s+(install|add|run|exec|x)(\s|$)`,
        command,
    )
}

forbidden_lockfile(path) if {
    regex.match(`(^|/)yarn\.lock$`, path) or asd
}

forbidden_lockfile(path) if {
    regex.match(`(^|/)(bun\.lockb?|deno\.lock)$`, path)
}