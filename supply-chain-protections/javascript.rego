package supply_chain.policies

import rego.v1

# Every rule below follows the same shape:
#   1. a comment saying what the rule requires and why,
#   2. the conditions that select a violation,
#   3. a finding whose message names the file, the problem, and the reason.
# Deny rules say "must"; warn rules say "should".

# ===========================================================================
# Package managers and lockfiles
# ===========================================================================

# Requires a package manager the policy knows how to secure.
# Only npm and pnpm have the supply-chain settings checked below.
deny contains finding if {
    some project in input.projects
    project.manager == "unknown"

    finding := policy_finding(
        concat(" ", [
            sprintf("%s has no packageManager field or lockfile, so its package manager is unknown.", [project.packagePath]),
            "Use pnpm (recommended) or npm and commit its lockfile.",
        ]),
        project.packagePath,
        "javascript/supported-package-manager",
    )
}

deny contains finding if {
    some project in input.projects
    not project.manager in {"npm", "pnpm", "unknown"}

    finding := policy_finding(
        concat(" ", [
            sprintf("%s uses the unsupported package manager %q.", [project.packagePath, project.manager]),
            "Use pnpm (recommended) or npm.",
        ]),
        project.packagePath,
        "javascript/supported-package-manager",
    )
}

# Recommends pnpm over npm, because pnpm has stronger supply-chain controls.
warn contains finding if {
    some project in input.projects
    project.manager == "npm"

    finding := policy_finding(
        concat(" ", [
            sprintf("%s should use pnpm instead of npm.", [project.packagePath]),
            "pnpm provides stronger supply-chain protections.",
        ]),
        project.packagePath,
        "javascript/prefer-pnpm",
    )
}

# Requires a committed lockfile, so installs use reviewed, reproducible versions.
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

# Rejects Yarn, Bun, and Deno lockfiles, because those package managers are not supported.
deny contains finding if {
    some path in input.trackedFiles
    is_unsupported_lockfile(path)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s belongs to an unsupported package manager.", [path]),
            "Remove it and use pnpm (recommended) or npm with its own lockfile.",
        ]),
        path,
        "javascript/unsupported-lockfile",
    )
}

# Rejects package-lock.json in pnpm projects, so npm cannot install from a second lockfile.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    package_lock := path_for(project.root, "package-lock.json")
    is_tracked(package_lock)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must be removed because %s uses pnpm.", [package_lock, project.packagePath]),
            "Use pnpm-lock.yaml only.",
        ]),
        package_lock,
        "javascript/pnpm-package-lock-forbidden",
    )
}

# ===========================================================================
# npm projects
# ===========================================================================

npmrc_required_settings := {
    "engine-strict": {
        "value": "true",
        "reason": "This rejects packages that require an incompatible npm or Node.js version.",
    },
    "allow-git": {
        "value": "root",
        "reason": "This blocks transitive dependencies fetched from Git repositories.",
    },
    "allow-remote": {
        "value": "root",
        "reason": "This blocks transitive dependencies fetched from remote URLs.",
    },
    "ignore-scripts": {
        "value": "true",
        "reason": "This disables dependency lifecycle scripts by default.",
    },
}

# Requires npm 11.10.0 or newer, the first version with every setting checked below.
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

# Requires an .npmrc, where npm reads its supply-chain settings.
deny contains finding if {
    some project in input.projects
    project.manager == "npm"
    project.npmrcPath == ""

    finding := policy_finding(
        concat(" ", [
            sprintf("%s has no applicable .npmrc.", [project.packagePath]),
            "Add and commit an .npmrc containing the required npm supply-chain settings.",
            "Rerun this check after adding it to get them listed.",
        ]),
        project.packagePath,
        "javascript/npmrc-required",
    )
}

# Requires the .npmrc settings in npmrc_required_settings; each entry gives its reason.
deny contains finding if {
    some project in input.projects
    project.manager == "npm"
    project.npmrcPath != ""
    some key, setting in npmrc_required_settings
    lower(sprintf("%v", [object.get(project.npmrc, key, "")])) != setting.value

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set %s=%s.", [project.npmrcPath, key, setting.value]),
            setting.reason,
        ]),
        project.npmrcPath,
        sprintf("javascript/npmrc-%s", [key]),
    )
}

# Requires a 7-day minimum release age, so compromised releases are usually
# caught and removed before they can be installed.
deny contains finding if {
    some project in input.projects
    project.manager == "npm"
    project.npmrcPath != ""
    not number_at_least(object.get(project.npmrc, "min-release-age", ""), 7)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set min-release-age to at least 7.", [project.npmrcPath]),
            "Packages must not be installed until seven days after publication.",
        ]),
        project.npmrcPath,
        "javascript/npmrc-min-release-age",
    )
}

# ===========================================================================
# pnpm projects
# ===========================================================================

pnpm_required_true_settings := {
    "engineStrict": "This rejects packages that require an incompatible pnpm or Node.js version.",
    "minimumReleaseAgeStrict": "This applies the minimum release age to all dependency versions.",
    "blockExoticSubdeps": "This blocks transitive Git and remote URL dependencies.",
    "strictDepBuilds": "This fails when a dependency lifecycle script has not been reviewed.",
}

# Requires engines.npm=disallow, so tools and automation cannot fall back to npm,
# which ignores the pnpm settings checked below.
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

# Requires pnpm 11.0.0 or newer, the first version with every setting checked below.
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

# Requires an .npmrc in pnpm projects, so npm reads engine-strict=true from it.
# pnpm 11 ignores this file except for auth and registry settings.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.npmrcPath == ""

    finding := policy_finding(
        concat(" ", [
            sprintf("%s has no applicable .npmrc.", [project.packagePath]),
            "Add and commit an .npmrc containing engine-strict=true,",
            "so npm refuses to install because of engines.npm=disallow.",
        ]),
        project.packagePath,
        "javascript/pnpm-npmrc-required",
    )
}

# Requires engine-strict=true in pnpm projects' .npmrc, because without it
# npm install and npm ci only warn about engines.npm=disallow and install anyway.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.npmrcPath != ""
    not is_true(object.get(project.npmrc, "engine-strict", false))

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set engine-strict=true.", [project.npmrcPath]),
            "Without it, npm only warns about engines.npm=disallow and installs anyway.",
        ]),
        project.npmrcPath,
        "javascript/pnpm-npmrc-engine-strict",
    )
}

# Requires a pnpm-workspace.yaml, where pnpm reads its supply-chain settings.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath == ""

    finding := policy_finding(
        concat(" ", [
            sprintf("%s has no applicable pnpm-workspace.yaml.", [project.packagePath]),
            "Add and commit one containing the required pnpm supply-chain settings.",
            "Rerun this check after adding it to get them listed.",
        ]),
        project.packagePath,
        "javascript/pnpm-workspace-required",
    )
}

# Requires the pnpm settings in pnpm_required_true_settings; each entry gives its reason.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    some key, reason in pnpm_required_true_settings
    not is_true(object.get(project.workspace, key, false))

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set %s: true.", [project.workspacePath, key]),
            reason,
        ]),
        project.workspacePath,
        sprintf("javascript/pnpm-workspace-%s", [key]),
    )
}

# Requires a 7-day (10,080-minute) minimum release age, so compromised releases
# are usually caught and removed before they can be installed.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    not number_at_least(object.get(project.workspace, "minimumReleaseAge", 0), 10080)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set minimumReleaseAge to at least 10080 minutes.", [project.workspacePath]),
            "Packages must not be installed until seven days after publication.",
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-minimum-release-age",
    )
}

# Requires pnpm to never continue with a pnpm version other than the pinned one,
# because that version may ignore these settings.
# pmOnFail: error stops pnpm. pmOnFail: download switches to the pinned version,
# so it is allowed only when packageManager pins an allowed version with a hash.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    not pm_on_fail_allowed(project, object.get(project.workspace, "pmOnFail", ""))

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set pmOnFail: error,", [project.workspacePath]),
            sprintf("or pmOnFail: download when %s pins packageManager", [project.packagePath]),
            "to pnpm 11.0.0 or newer with a SHA-512 hash (e.g. pnpm@11.0.0+sha512.<hash>, written by `corepack use`).",
            "This stops pnpm from continuing with a version other than the pinned one.",
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-pm-on-fail",
    )
}

pm_on_fail_allowed(_, "error")

pm_on_fail_allowed(project, "download") if {
    package_manager_hash_pinned_at_least(project.package, "pnpm", "11.0.0")
}

# Requires pnpm to fail when the running pnpm version does not match packageManager,
# so older pnpm versions cannot silently ignore unsupported supply-chain settings.
# Newer pnpm versions have deprecated this setting, so it is exempt when pnpm 11.0.0
# or newer is proven: engines.pnpm makes pnpm 5-10 refuse to install or run scripts,
# and the pinned packageManager makes pnpm 10 switch to that exact version.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    not is_true(object.get(project.workspace, "packageManagerStrictVersion", false))
    not pnpm_version_proven(project.package, "11.0.0")

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set packageManagerStrictVersion: true,", [project.workspacePath]),
            sprintf("unless %s pins packageManager to pnpm 11.0.0 or newer (e.g. pnpm@11.0.0)", [project.packagePath]),
            "and sets engines.pnpm to exclude versions older than 11.0.0.",
            "This prevents older pnpm versions from ignoring unsupported supply-chain settings.",
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-packageManagerStrictVersion",
    )
}

# Requires trustPolicy: no-downgrade, so a release published with weaker provenance
# than earlier releases, which can mean a compromised publisher, is not installed.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    object.get(project.workspace, "trustPolicy", "") != "no-downgrade"

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must set trustPolicy: no-downgrade.", [project.workspacePath]),
            "This prevents installing a package version when its trust level",
            "is lower than previously published versions.",
            "For exceptions, use trustPolicyExclude for specific packages",
            "or trustPolicyIgnoreAfter for versions older than a given age.",
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-trust-policy",
    )
}

# Rejects dangerouslyAllowAllBuilds, which lets every dependency run lifecycle scripts.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    project.workspacePath != ""
    is_true(object.get(project.workspace, "dangerouslyAllowAllBuilds", false))

    finding := policy_finding(
        concat(" ", [
            sprintf("%s must not set dangerouslyAllowAllBuilds: true.", [project.workspacePath]),
            "Dependency lifecycle scripts must be blocked by default",
            "and enabled only for reviewed packages.",
        ]),
        project.workspacePath,
        "javascript/pnpm-workspace-dangerous-builds",
    )
}

# ===========================================================================
# Package scripts
# ===========================================================================

# Rejects scripts that download and run packages, because those bypass the lockfile.
deny contains finding if {
    some project in input.projects
    some script in object.get(project.package, "scripts", {})
    runs_inline_package(script)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s contains a script that installs or executes a package inline.", [project.packagePath]),
            "Inline packages bypass the lockfile and the release-age and trust checks.",
            "Add the tool as a project dependency and invoke its binary directly;",
            "package scripts resolve local binaries automatically.",
        ]),
        project.packagePath,
        "javascript/inline-package-install-script",
    )
}

# Rejects npm and npx in pnpm projects' scripts, because npm ignores the pnpm settings.
deny contains finding if {
    some project in input.projects
    project.manager == "pnpm"
    some script in object.get(project.package, "scripts", {})
    runs_npm(script)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s contains a script that runs npm or npx.", [project.packagePath]),
            "The project uses pnpm; use the equivalent pnpm command",
            "so the pnpm lockfile and security settings are enforced.",
        ]),
        project.packagePath,
        "javascript/npm-command-in-pnpm-script",
    )
}

# ===========================================================================
# CI and container builds
# ===========================================================================

# Rejects Yarn, Bun, and Deno commands, because those package managers are not supported.
deny contains finding if {
    some command in input.ciCommands
    runs_unsupported_manager(command.command)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s runs Yarn, Bun, or Deno in a CI or container build.", [command.path]),
            "Use only pnpm (recommended) or npm.",
        ]),
        command.path,
        "javascript/unsupported-ci-package-manager",
    )
}

# Rejects commands that download and run packages, because those bypass the lockfile.
deny contains finding if {
    some command in input.ciCommands
    runs_inline_package(command.command)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s installs or executes a package inline.", [command.path]),
            "Inline packages bypass the lockfile and the release-age and trust checks.",
            "Add the tool as a project dependency and invoke its binary",
            "through a package script instead.",
        ]),
        command.path,
        "javascript/inline-package-install",
    )
}

# Requires npm ci, because npm install may update the lockfile instead of following it.
deny contains finding if {
    some command in input.ciCommands
    runs_npm_install(command.command)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s runs npm install in a CI or container build.", [command.path]),
            "Use npm ci for a clean, lockfile-based install.",
        ]),
        command.path,
        "javascript/npm-ci-required",
    )
}

# Rejects npm and npx in pnpm projects, because npm ignores the pnpm lockfile and settings.
deny contains finding if {
    some command in input.ciCommands
    project := project_for(command.projectRoot)
    project.manager == "pnpm"
    runs_npm(command.command)

    finding := policy_finding(
        concat(" ", [
            sprintf("%s runs npm or npx in a pnpm project.", [command.path]),
            "Use the equivalent pnpm command",
            "so the pnpm lockfile and security settings are enforced.",
        ]),
        command.path,
        "javascript/npm-command-in-pnpm-ci",
    )
}

# Requires CI=true for pnpm commands, because pnpm then refuses to change
# the lockfile during install.
deny contains finding if {
    some command in input.ciCommands
    runs_pnpm(command.command)
    project := project_for(command.projectRoot)
    project.manager == "pnpm"
    not is_true(object.get(command.env, "CI", false))

    finding := policy_finding(
        concat(" ", [
            sprintf("%s runs pnpm without CI=true.", [command.path]),
            "Set CI=true before running pnpm in CI and container builds",
            "so installs fail instead of changing the lockfile.",
        ]),
        command.path,
        "javascript/pnpm-ci-environment",
    )
}

# Requires container builds to copy the lockfile, so the image installs the locked versions.
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
