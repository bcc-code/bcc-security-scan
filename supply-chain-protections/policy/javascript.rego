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

deny contains finding if {
    some project in input.projects
    project.manager != "npm"
    project.manager != "pnpm"

    finding := policy_finding(
        sprintf("%s uses unsupported package manager %s", [
            project.root,
            project.manager,
        ]),
        project.packagePath,
        "javascript/supported-package-manager",
    )
}

warn contains finding if {
    some project in input.projects
    project.manager == "npm"

    finding := policy_finding(
        sprintf("%s uses npm; pnpm is preferred", [project.root]),
        project.packagePath,
        "javascript/prefer-pnpm",
    )
}

deny contains finding if {
    some project in input.projects
    project.lockfilePath == ""

    finding := policy_finding(
        sprintf("%s requires an applicable lockfile", [project.packagePath]),
        project.packagePath,
        "javascript/lockfile-required",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    package_lock := path_for(project.root, "package-lock.json")
    tracked(package_lock)

    finding := policy_finding(
        sprintf("%s must not contain package-lock.json", [project.root]),
        package_lock,
        "javascript/pnpm-package-lock-forbidden",
    )
}

deny contains finding if {
    some path in input.trackedFiles
    forbidden_lockfile(path)

    finding := policy_finding(
        sprintf("Unsupported package-manager lockfile: %s", [path]),
        path,
        "javascript/unsupported-lockfile",
    )
}

deny contains finding if {
    some build in input.containerBuilds
    project := project_for(build.projectRoot)
    lockfile := project.lockfilePath
    lockfile != ""
    not lockfile in build.copiedFiles

    finding := policy_finding(
        sprintf("%s does not copy %s into its build context", [
            build.path,
            lockfile,
        ]),
        build.path,
        "javascript/container-lockfile-copy",
    )
}

deny contains finding if {
    some command in input.ciCommands
    project := project_for(command.projectRoot)
    project.manager == "pnpm"
    not true_value(object.get(command.env, "CI", false))

    finding := policy_finding(
        sprintf("%s must set CI=true before pnpm commands", [command.path]),
        command.path,
        "javascript/pnpm-ci-environment",
    )
}

deny contains finding if {
    some command in input.ciCommands
    project := project_for(command.projectRoot)
    project.manager == "npm"
    npm_install(command.command)

    finding := policy_finding(
        sprintf("%s must use npm ci instead of npm install", [command.path]),
        command.path,
        "javascript/npm-ci-required",
    )
}

deny contains finding if {
    some command in input.ciCommands
    project := project_for(command.projectRoot)
    project.manager == "pnpm"
    uses_npm(command.command)

    finding := policy_finding(
        sprintf("%s uses npm in a pnpm project", [command.path]),
        command.path,
        "javascript/npm-command-in-pnpm-ci",
    )
}

deny contains finding if {
    some command in input.ciCommands
    uses_forbidden_manager(command.command)

    finding := policy_finding(
        sprintf("%s uses an unsupported package manager", [command.path]),
        command.path,
        "javascript/unsupported-ci-package-manager",
    )
}

deny contains finding if {
    some project in input.projects
    some _, script in object.get(project.package, "scripts", {})
    project.manager == "pnpm"
    uses_npm(script)

    finding := policy_finding(
        sprintf("%s contains an npm command in package scripts", [
            project.packagePath,
        ]),
        project.packagePath,
        "javascript/npm-command-in-pnpm-script",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "npm"
    engines := object.get(project.package, "engines", {})
    not engine_at_least(object.get(engines, "npm", ""), "11.10.0")

    finding := policy_finding(
        sprintf("%s must require npm >=11.10.0", [project.packagePath]),
        project.packagePath,
        "javascript/minimum-npm-version",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "npm"
    project.npmrcPath == ""

    finding := policy_finding(
        sprintf("%s requires an applicable .npmrc", [project.packagePath]),
        project.packagePath,
        "javascript/npmrc-required",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "npm"
    project.npmrcPath != ""
    some key, expected in npmrc_required
    actual := lower(sprintf("%v", [object.get(project.npmrc, key, "")]))
    actual != expected

    finding := policy_finding(
        sprintf("%s must set %s=%s", [
            project.npmrcPath,
            key,
            expected,
        ]),
        project.npmrcPath,
        sprintf("javascript/npmrc-%s", [key]),
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "npm"
    project.npmrcPath != ""
    not number_at_least(
        object.get(project.npmrc, "min-release-age", ""),
        7,
    )

    finding := policy_finding(
        sprintf("%s must set min-release-age>=7", [project.npmrcPath]),
        project.npmrcPath,
        "javascript/npmrc-min-release-age",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    engines := object.get(project.package, "engines", {})
    object.get(engines, "npm", "") != "disallow"

    finding := policy_finding(
        sprintf("%s must set engines.npm to disallow", [project.packagePath]),
        project.packagePath,
        "javascript/pnpm-disallow-npm",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    engines := object.get(project.package, "engines", {})
    not engine_at_least(object.get(engines, "pnpm", ""), "11.0.0")

    finding := policy_finding(
        sprintf("%s must require pnpm >=11.0.0", [project.packagePath]),
        project.packagePath,
        "javascript/minimum-pnpm-version",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath == ""

    finding := policy_finding(
        sprintf(
            "%s requires an applicable pnpm-workspace.yaml",
            [project.packagePath],
        ),
        project.packagePath,
        "javascript/pnpm-workspace-required",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    some key in pnpm_true_required
    not true_value(object.get(project.workspace, key, false))

    finding := policy_finding(
        sprintf("%s must set %s=true", [project.workspacePath, key]),
        project.workspacePath,
        sprintf("javascript/pnpm-workspace-%s", [key]),
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    object.get(project.workspace, "pmOnFail", "") != "error"

    finding := policy_finding(
        sprintf("%s must set pmOnFail=error", [project.workspacePath]),
        project.workspacePath,
        "javascript/pnpm-workspace-pm-on-fail",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    not number_at_least(
        object.get(project.workspace, "minimumReleaseAge", 0),
        10080,
    )

    finding := policy_finding(
        sprintf("%s must set minimumReleaseAge>=10080", [
            project.workspacePath,
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-minimum-release-age",
    )
}

deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    true_value(object.get(
        project.workspace,
        "dangerouslyAllowAllBuilds",
        false,
    ))

    finding := policy_finding(
        sprintf("%s must not allow all dependency builds", [
            project.workspacePath,
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-dangerous-builds",
    )
}