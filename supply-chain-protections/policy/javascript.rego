package supply_chain.policies

import rego.v1

npmrc_required := {
    "engine-strict": "true",
    "allow-git": "root",
    "allow-remote": "root",
    "ignore-scripts": "true",
}

pnpm_true_required := {
    "engineStrict",
    "minimumReleaseAgeStrict",
    "blockExoticSubdeps",
    "strictDepBuilds",
}

deny contains msg if {
    some project in input.projects
    project.manager != "npm"
    project.manager != "pnpm"
    msg := sprintf("%s uses unsupported package manager %s", [
        project.root,
        project.manager,
    ])
}

warn contains msg if {
    some project in input.projects
    project.manager == "npm"
    msg := sprintf("%s uses npm; pnpm is preferred", [project.root])
}

deny contains msg if {
    some project in input.projects
    project.lockfilePath == ""
    msg := sprintf("%s requires an applicable lockfile", [project.packagePath])
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    tracked(path_for(project.root, "package-lock.json"))
    msg := sprintf("%s must not contain package-lock.json", [project.root])
}

deny contains msg if {
    some path in input.trackedFiles
    forbidden_lockfile(path)
    msg := sprintf("Unsupported package-manager lockfile: %s", [path])
}

deny contains msg if {
    some build in input.containerBuilds
    project := project_for(build.projectRoot)
    lockfile := project.lockfilePath
    not lockfile in build.copiedFiles
    msg := sprintf("%s does not copy %s into its build context", [
        build.path,
        lockfile,
    ])
}

deny contains msg if {
    some command in input.ciCommands
    project := project_for(command.projectRoot)
    project.manager == "pnpm"
    not true_value(object.get(command.env, "CI", false))
    msg := sprintf("%s must set CI=true before pnpm commands", [command.path])
}

deny contains msg if {
    some command in input.ciCommands
    project := project_for(command.projectRoot)
    project.manager == "npm"
    npm_install(command.command)
    msg := sprintf("%s must use npm ci instead of npm install", [command.path])
}

deny contains msg if {
    some command in input.ciCommands
    project := project_for(command.projectRoot)
    project.manager == "pnpm"
    uses_npm(command.command)
    msg := sprintf("%s uses npm in a pnpm project", [command.path])
}

deny contains msg if {
    some command in input.ciCommands
    uses_forbidden_manager(command.command)
    msg := sprintf("%s uses an unsupported package manager", [command.path])
}

deny contains msg if {
    some project in input.projects
    some _, script in object.get(project.package, "scripts", {})
    project.manager == "pnpm"
    uses_npm(script)
    msg := sprintf("%s contains an npm command in package scripts", [
        project.packagePath,
    ])
}

deny contains msg if {
    some project in input.projects
    project.manager == "npm"
    engines := object.get(project.package, "engines", {})
    not engine_at_least(object.get(engines, "npm", ""), "11.10.0")
    msg := sprintf("%s must require npm >=11.10.0", [project.packagePath])
}

deny contains msg if {
    some project in input.projects
    project.manager == "npm"
    project.npmrcPath == ""
    msg := sprintf("%s requires an applicable .npmrc", [project.packagePath])
}

deny contains msg if {
    some project in input.projects
    project.manager == "npm"
    some key, expected in npmrc_required
    actual := lower(sprintf("%v", [object.get(project.npmrc, key, "")]))
    actual != expected
    msg := sprintf("%s must set %s=%s", [
        project.npmrcPath,
        key,
        expected,
    ])
}

deny contains msg if {
    some project in input.projects
    project.manager == "npm"
    not number_at_least(object.get(project.npmrc, "min-release-age", ""), 7)
    msg := sprintf("%s must set min-release-age>=7", [project.npmrcPath])
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    engines := object.get(project.package, "engines", {})
    object.get(engines, "npm", "") != "disallow"
    msg := sprintf("%s must set engines.npm to disallow", [project.packagePath])
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    engines := object.get(project.package, "engines", {})
    not engine_at_least(object.get(engines, "pnpm", ""), "11.0.0")
    msg := sprintf("%s must require pnpm >=11.0.0", [project.packagePath])
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath == ""
    msg := sprintf(
        "%s requires an applicable pnpm-workspace.yaml",
        [project.packagePath],
    )
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    some key in pnpm_true_required
    not true_value(object.get(project.workspace, key, false))
    msg := sprintf("%s must set %s=true", [project.workspacePath, key])
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    object.get(project.workspace, "pmOnFail", "") != "error"
    msg := sprintf("%s must set pmOnFail=error", [project.workspacePath])
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    not number_at_least(
        object.get(project.workspace, "minimumReleaseAge", 0),
        10080,
    )
    msg := sprintf("%s must set minimumReleaseAge>=10080", [
        project.workspacePath,
    ])
}

deny contains msg if {
    some project in input.projects
    project.manager == "pnpm"
    true_value(object.get(
        project.workspace,
        "dangerouslyAllowAllBuilds",
        false,
    ))
    msg := sprintf("%s must not allow all dependency builds", [
        project.workspacePath,
    ])
}