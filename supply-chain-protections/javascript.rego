package supply_chain.policies

import rego.v1

npmrc_required := {
    "engine-strict": "true",
    "allow-git": "root",
    "allow-remote": "root",
    "ignore-scripts": "true",
}

npmrc_requirement_reason := {
    "engine-strict": "This rejects packages that require an incompatible NPM or Node.js version.",
    "allow-git": "This blocks transitive dependencies fetched from Git repositories.",
    "allow-remote": "This blocks transitive dependencies fetched from remote URLs.",
    "ignore-scripts": "This disables dependency lifecycle scripts by default.",
}

pnpm_true_required := {
    "engineStrict",
    "minimumReleaseAgeStrict",
    "blockExoticSubdeps",
    "strictDepBuilds",
}

pnpm_requirement_reason := {
    "engineStrict": "This rejects packages that require an incompatible PNPM or Node.js version.",
    "minimumReleaseAgeStrict": "This applies the minimum release age to all dependency versions.",
    "blockExoticSubdeps": "This blocks transitive Git and remote URL dependencies.",
    "strictDepBuilds": "This fails when a dependency lifecycle script has not been reviewed.",
}

# Recommends setting packageManagerStrictVersion to true for pnpm to prevent old versions from being used.
# Note that new versions have deprecated this setting, but old versions don't understand the new setting.
warn contains finding if {
    message_part1 := sprintf("%s should set packageManagerStrictVersion=true.", [project.workspacePath])
    message_part2 := "This prevents older pnpm versions from ignoring unsupported supply-chain settings."
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    not true_value(object.get(project.workspace, "packageManagerStrictVersion", false))

    finding := policy_finding(
        concat(" ", [message_part1, message_part2]),
        project.workspacePath,
        "javascript/pnpm-workspace-packageManagerStrictVersion",
    )
}

# Recommends pnpm over npm because pnpm provides stronger supply-chain controls.
warn contains finding if {
    some project in input.projects
    project.manager == "npm"

    finding := policy_finding(
        concat(" ", [
            sprintf("%s uses npm.", [project.root]),
            "pnpm is recommended because it provides stronger supply-chain protections.",
        ]),
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
        sprintf("%s configures the unsupported package manager %q. Use pnpm (recommended) or npm.", [
            project.packagePath,
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
        concat(" ", [
            sprintf("%s has no applicable lockfile.", [project.packagePath]),
            "Generate the lockfile for the configured package manager and commit it to version control.",
        ]),
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
        concat(" ", [
            sprintf("%s is configured for pnpm but contains package-lock.json.", [project.root]),
            "Remove package-lock.json and use pnpm-lock.yaml only.",
        ]),
        package_lock,
        "javascript/pnpm-package-lock-forbidden",
    )
}

# Rejects lockfiles created by unsupported package managers such as Yarn, Bun, and Deno.
deny contains finding if {
    some path in input.trackedFiles
    forbidden_lockfile(path)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s belongs to an unsupported package manager.", [path]),
            "Remove it and use pnpm (recommended) or npm with their respective lockfile.",
        ]),
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
        concat(" ", [
            sprintf("%s does not copy %s.", [build.path, lockfile]),
            "Copy the lockfile before installing dependencies",
            "so the container build uses the locked versions.",
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
        concat(" ", [
            sprintf("%s runs pnpm without CI=true.", [command.path]),
            "Set CI=true before running pnpm in CI and container builds.",
        ]),
        command.path,
        "javascript/pnpm-ci-environment",
    )
}

# Requires npm ci instead of npm install for reproducible CI and container installs.
deny contains finding if {
    some command in input.ciCommands
    npm_install(command.command)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s runs npm install in a CI or container build.", [command.path]),
            "Use npm ci for a clean, lockfile-based install.",
        ]),
        command.path,
        "javascript/npm-ci-required",
    )
}

# Prevents dynamic package installs and execution in CI and container build flows.
deny contains finding if {
    some command in input.ciCommands
    uses_inline_install(command.command)

    message := concat(" ", [
        sprintf("%s installs or executes a package inline.", [command.path]),
        "Add the tool as a project dependency and invoke its binary",
        "through a package script instead. Using npx/pnpx adds risks.",
    ])

    finding := policy_finding(
        message,
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
        concat(" ", [
            sprintf("%s runs npm or npx in a pnpm project.", [command.path]),
            "Use the equivalent pnpm command so the pnpm lockfile",
            "and security settings are enforced.",
        ]),
        command.path,
        "javascript/npm-command-in-pnpm-ci",
    )
}

# Prevents Yarn, Bun, and Deno commands in CI and container build flows.
deny contains finding if {
    some command in input.ciCommands
    uses_forbidden_manager(command.command)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s runs Yarn, Bun, or Deno in a CI or container build.", [command.path]),
            "Use only pnpm (recommended) or npm.",
        ]),
        command.path,
        "javascript/unsupported-ci-package-manager",
    )
}

# Prevents package scripts from installing or executing packages inline.
deny contains finding if {
    some project in input.projects
    some _, script in object.get(project.package, "scripts", {})
    uses_inline_install(script)

    message := concat(" ", [
        sprintf("%s contains a script that installs or executes a package inline.", [project.packagePath]),
        "Add the tool as a project dependency and invoke its binary directly;",
        "package scripts resolve local binaries automatically. Npx/Pnpx adds risks.",
    ])

    finding := policy_finding(
        message,
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
        concat(" ", [
            sprintf("%s contains a package script that runs npm or npx.", [project.packagePath]),
            "The project uses pnpm; use the equivalent pnpm command instead.",
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
        concat(" ", [
            sprintf("%s must set engines.npm to exclude versions older than 11.10.0.", [project.packagePath]),
            "Older npm versions do not support the required supply-chain protections.",
        ]),
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
        concat(" ", [
            sprintf("%s has no applicable .npmrc.", [project.packagePath]),
            "Add and commit an .npmrc containing the required npm supply-chain settings.",
            "Rerun this checker after adding it to get them listed.",
        ]),
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
        concat(" ", [
            sprintf("%s must set %s=%s.", [project.npmrcPath, key, expected]),
            npmrc_requirement_reason[key],
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
        concat(" ", [
            sprintf("%s must set min-release-age to at least 7.", [project.npmrcPath]),
            "Packages must not be installed until seven days after publication.",
        ]),
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
        concat(" ", [
            sprintf("%s must set engines.npm=disallow because the project uses pnpm.", [project.packagePath]),
            "This prevents tools and automation from falling back to npm.",
        ]),
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
        concat(" ", [
            sprintf("%s must set engines.pnpm to exclude versions older than 11.0.0.", [project.packagePath]),
            "Older pnpm versions do not support the required supply-chain protections.",
        ]),
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
        concat(" ", [
            sprintf("%s has no applicable pnpm-workspace.yaml.", [project.packagePath]),
            "Add and commit one containing the required pnpm supply-chain settings.",
            "Rerun this checker after adding it to get them listed.",
        ]),
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
        concat(" ", [
            sprintf("%s must set %s=true.", [project.workspacePath, key]),
            pnpm_requirement_reason[key],
        ]),
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
        concat(" ", [
            sprintf("%s must set pmOnFail=error", [project.workspacePath]),
            "so pnpm stops when the configured package-manager version cannot be used.",
        ]),
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
        concat(" ", [
            sprintf("%s must set minimumReleaseAge to at least 10080 minutes", [project.workspacePath]),
            "(seven days) so newly published packages cannot be installed.",
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
        concat(" ", [
            sprintf("%s must not set dangerouslyAllowAllBuilds=true.", [project.workspacePath]),
            "Dependency lifecycle scripts must be blocked by default",
            "and enabled only for reviewed packages.",
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-dangerous-builds",
    )
}