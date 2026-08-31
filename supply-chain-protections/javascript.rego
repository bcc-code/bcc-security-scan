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

# Recommends pnpm over npm because pnpm provides stronger supply-chain controls.
warn contains finding if {
    some project in input.projects
    project.manager == "npm"

    finding := policy_finding(
        sprintf("%s uses npm; pnpm is preferred", [project.root]),
        project.packagePath,
        "javascript/prefer-pnpm",
    )
}

# Allows only npm and pnpm package managers in JavaScript projects.
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

# Requires every JavaScript project to have an applicable committed lockfile.
# lockfilePath is computed by the inventory action
deny contains finding if {
    some project in input.projects
    project.lockfilePath == ""

    finding := policy_finding(
        sprintf("%s requires an applicable lockfile", [project.packagePath]),
        project.packagePath,
        "javascript/lockfile-required",
    )
}

# Prevents npm's package-lock.json from being committed in a pnpm project.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    package_lock := path_for(project.root, "package-lock.json")
    tracked(package_lock)

    finding := policy_finding(
        sprintf("%s must not contain package-lock.json, it is managed using pnpm", [project.root]),
        package_lock,
        "javascript/pnpm-package-lock-forbidden",
    )
}

# Rejects lockfiles created by unsupported package managers such as Yarn, Bun, and Deno.
deny contains finding if {
    some path in input.trackedFiles
    forbidden_lockfile(path)

    finding := policy_finding(
        sprintf("Unsupported package-manager lockfile: %s. You should not use this package manager.", [path]),
        path,
        "javascript/unsupported-lockfile",
    )
}

# Requires container builds to copy the project's lockfile for reproducible installs.
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

# Requires CI=true for pnpm commands in CI and container build flows.
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

# Requires npm ci instead of npm install for reproducible CI and container installs.
deny contains finding if {
    some command in input.ciCommands
    npm_install(command.command)

    finding := policy_finding(
        sprintf("%s must use npm ci instead of npm install", [command.path]),
        command.path,
        "javascript/npm-ci-required",
    )
}

# Prevents dynamic package installs and execution in CI and container build flows.
deny contains finding if {
    inline_install_remediation :=
    "Instead of npx, add a package script that references the binary directly, without npx."
    some command in input.ciCommands
    uses_inline_install(command.command)

    message := sprintf(
        "%s installs or executes a package inline.",
        [command.path],
    )

    finding := policy_finding(
        concat(" ", [message, inline_install_remediation]),
        command.path,
        "javascript/inline-package-install",
    )
}

# Prevents npm and npx commands in pnpm-based CI and container build flows.
# This is to prevent running npm commands without supply chain safeguards
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

# Prevents Yarn, Bun, and Deno commands in CI and container build flows.
deny contains finding if {
    some command in input.ciCommands
    uses_forbidden_manager(command.command)

    finding := policy_finding(
        sprintf("%s uses an unsupported package manager", [command.path]),
        command.path,
        "javascript/unsupported-ci-package-manager",
    )
}

# Prevents package scripts from installing or executing packages inline.
deny contains finding if {
    inline_install_remediation1 :=
    "If using npx/pnpx or similar, drop using it and call binary directly."
    inline_install_remediation2 :=
    "Using npx/pnpx prefix is not required within package scripts."
    some project in input.projects
    some _, script in object.get(project.package, "scripts", {})
    uses_inline_install(script)

    message := sprintf(
        "%s contains an inline package install or execution.",
        [project.packagePath],
    )

    finding := policy_finding(
        concat(" ", [message, inline_install_remediation1, inline_install_remediation2]),
        project.packagePath,
        "javascript/inline-package-install-script",
    )
}

# Prevents package scripts from invoking npm or npx in pnpm projects.
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

# Requires npm projects to declare engines.npm >=11.10.0.
# These versions supports all the supply chain settings we want.
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

# Requires npm projects to have an applicable .npmrc alongside package.json.
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

# Enforces npm .npmrc safeguards for engines, exotic dependencies, and lifecycle scripts.
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

# Requires npm packages to be at least seven days old before they can be installed.
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

# Disallows npm through engines.npm in pnpm projects.
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

# Requires pnpm projects to declare engines.pnpm >=11.0.0.
# These versions supports all the supply chain settings we want.
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

# Requires pnpm projects to have an applicable pnpm-workspace.yaml.
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

# Enables strict pnpm safeguards for engines, package age, exotic dependencies, and builds.
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

# Requires pnpm to fail when its configured package manager version does not match.
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

# Requires pnpm packages to be at least seven days (10,080 minutes) old.
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

# Prevents pnpm from allowing lifecycle builds for every dependency.
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