package supply_chain_tests.javascript_test

import data.supply_chain.policies
import rego.v1

pnpm_project := {
	"root": ".",
	"manager": "pnpm",
	"packagePath": "package.json",
	"package": {},
	"npmrcPath": ".npmrc",
	"npmrc": {"engine-strict": "true"},
	"workspacePath": "pnpm-workspace.yaml",
	"workspace": {},
	"lockfilePath": "pnpm-lock.yaml",
}

finding_ids(findings) := {finding.policy_id | some finding in findings}

test_pnpm_ci_environment_flags_pnpm_without_ci if {
	findings := policies.deny with input as {
		"projects": [pnpm_project],
		"ciCommands": [{"path": "Dockerfile", "projectRoot": ".", "command": "pnpm install", "env": {}}],
	}
	"javascript/pnpm-ci-environment" in finding_ids(findings)
}

test_pnpm_ci_environment_accepts_ci_true if {
	findings := policies.deny with input as {
		"projects": [pnpm_project],
		"ciCommands": [{"path": "Dockerfile", "projectRoot": ".", "command": "pnpm install", "env": {"CI": "true"}}],
	}
	not "javascript/pnpm-ci-environment" in finding_ids(findings)
}

test_pnpm_ci_environment_ignores_other_commands if {
	findings := policies.deny with input as {
		"projects": [pnpm_project],
		"ciCommands": [{"path": "Dockerfile", "projectRoot": ".", "command": "apt-get install -y curl", "env": {}}],
	}
	not "javascript/pnpm-ci-environment" in finding_ids(findings)
}

test_unknown_package_manager_message_explains_detection if {
	findings := policies.deny with input as {"projects": [object.union(pnpm_project, {"manager": "unknown"})]}
	some finding in findings
	finding.policy_id == "javascript/supported-package-manager"
	contains(finding.msg, "package manager is unknown")
}

dev_engines_pnpm := {"devEngines": {"packageManager": {"name": "pnpm", "version": "11.2.3"}}}

pm_on_fail_flagged(package_document, pm_on_fail) if {
	project := object.union(pnpm_project, {"package": package_document, "workspace": {"pmOnFail": pm_on_fail}})
	findings := policies.deny with input as {"projects": [project]}
	"javascript/pnpm-workspace-pm-on-fail" in finding_ids(findings)
}

test_pm_on_fail_error_is_allowed if {
	not pm_on_fail_flagged({}, "error")
}

test_pm_on_fail_download_is_allowed_with_exact_dev_engines_pin if {
	not pm_on_fail_flagged(dev_engines_pnpm, "download")
}

test_pm_on_fail_download_is_rejected_without_exact_dev_engines_pin if {
	every package_document in [
		{},
		{"packageManager": "pnpm@11.2.3"},
		{"devEngines": {"packageManager": {"name": "pnpm", "version": "^11.0.0"}}},
	] {
		pm_on_fail_flagged(package_document, "download")
	}
}

test_pm_on_fail_other_values_are_rejected if {
	every value in ["", "warn", "ignore"] {
		pm_on_fail_flagged(dev_engines_pnpm, value)
	}
}

# pnpm ignores devEngines.packageManager in workspace sub-packages.
test_pm_on_fail_download_uses_the_workspace_package if {
	sub_package := object.union(pnpm_project, {
		"root": "apps/web",
		"packagePath": "apps/web/package.json",
		"package": dev_engines_pnpm,
		"workspace": {"pmOnFail": "download"},
	})
	root := object.union(pnpm_project, {"workspace": {"pmOnFail": "download"}})
	findings := policies.deny with input as {"projects": [root, sub_package]}
	pm_on_fail := [finding | some finding in findings; finding.policy_id == "javascript/pnpm-workspace-pm-on-fail"]

	# One finding for the workspace, naming the root package.json.
	count(pm_on_fail) == 1
	contains(pm_on_fail[0].msg, "when package.json sets devEngines.packageManager")
}

test_pnpm_ci_environment_skips_github_documents if {
	findings := policies.deny with input as {
		"projects": [pnpm_project],
		"githubDocuments": [{"path": ".github/workflows/ci.yml", "document": {}}],
		"ciCommands": [{"path": ".github/workflows/ci.yml", "projectRoot": ".", "command": "pnpm install", "env": {}}],
	}
	not "javascript/pnpm-ci-environment" in finding_ids(findings)
}

test_pnpm_npmrc_is_required if {
	project := object.union(pnpm_project, {"npmrcPath": "", "npmrc": {}})
	findings := policies.deny with input as {"projects": [project]}
	"javascript/pnpm-npmrc-required" in finding_ids(findings)
}

test_pnpm_npmrc_requires_engine_strict if {
	project := object.union(pnpm_project, {"npmrc": {"engine-strict": "false"}})
	findings := policies.deny with input as {"projects": [project]}
	"javascript/pnpm-npmrc-engine-strict" in finding_ids(findings)
}

test_pnpm_npmrc_accepts_engine_strict if {
	findings := policies.deny with input as {"projects": [pnpm_project]}
	not "javascript/pnpm-npmrc-required" in finding_ids(findings)
	not "javascript/pnpm-npmrc-engine-strict" in finding_ids(findings)
}

sub_package := object.union(pnpm_project, {
	"root": "apps/web",
	"packagePath": "apps/web/package.json",
	"npmrcPath": "apps/web/.npmrc",
})

# npm reads only the .npmrc next to the package it runs in.
test_pnpm_npmrc_is_required_next_to_every_package if {
	inherited := object.union(sub_package, {"npmrcPath": ".npmrc"})
	findings := policies.deny with input as {"projects": [pnpm_project, inherited]}
	some finding in findings
	finding.policy_id == "javascript/pnpm-npmrc-required"
	finding._loc.file == "apps/web/.npmrc"
}

test_pnpm_npmrc_engine_strict_checks_the_own_npmrc if {
	project := object.union(sub_package, {"npmrc": {"engine-strict": "false"}})
	findings := policies.deny with input as {"projects": [pnpm_project, project]}
	some finding in findings
	finding.policy_id == "javascript/pnpm-npmrc-engine-strict"
	finding._loc.file == "apps/web/.npmrc"
}

# engines.pnpm in the workspace package already stops older pnpm versions from installing.
test_minimum_pnpm_version_checks_only_the_workspace_package if {
	findings := policies.deny with input as {"projects": [pnpm_project, sub_package]}
	files := {finding._loc.file | some finding in findings; finding.policy_id == "javascript/minimum-pnpm-version"}
	files == {"package.json"}
}

minimum_pnpm_flagged(constraint) if {
	project := object.union(pnpm_project, {"package": {"engines": {"pnpm": constraint}}})
	findings := policies.deny with input as {"projects": [project]}
	"javascript/minimum-pnpm-version" in finding_ids(findings)
}

# pnpm 11.0.0 to 11.1.2 install a lockfile that pins a version younger than minimumReleaseAge.
test_minimum_pnpm_version_excludes_versions_without_lockfile_age_checks if {
	minimum_pnpm_flagged(">=11.0.0")
	minimum_pnpm_flagged(">=11.1.2")
	not minimum_pnpm_flagged(">=11.1.3")
	not minimum_pnpm_flagged(">=12.0.0")
}

# Without a workspace package, nothing sets engines.pnpm for the workspace.
test_pnpm_workspace_package_is_required if {
	findings := policies.deny with input as {"projects": [sub_package]}
	some finding in findings
	finding.policy_id == "javascript/pnpm-workspace-package-required"
	finding._loc.file == "pnpm-workspace.yaml"
	contains(finding.msg, "package.json must exist next to pnpm-workspace.yaml")
}

test_pnpm_workspace_package_is_accepted_when_present if {
	findings := policies.deny with input as {"projects": [pnpm_project, sub_package]}
	not "javascript/pnpm-workspace-package-required" in finding_ids(findings)
}

test_pnpm_workspace_package_is_reported_once_per_workspace if {
	other := object.union(sub_package, {"root": "apps/api", "packagePath": "apps/api/package.json", "npmrcPath": "apps/api/.npmrc"})
	findings := policies.deny with input as {"projects": [sub_package, other]}
	count([finding | some finding in findings; finding.policy_id == "javascript/pnpm-workspace-package-required"]) == 1
}

dev_engines_flagged(package_manager) if {
	project := object.union(pnpm_project, {"package": {"devEngines": {"packageManager": package_manager}}})
	findings := policies.deny with input as {"projects": [project]}
	"javascript/pnpm-dev-engines-on-fail" in finding_ids(findings)
}

test_dev_engines_on_fail_allows_safe_values if {
	not dev_engines_flagged({"name": "pnpm", "version": "11.2.3"})
	not dev_engines_flagged({"name": "pnpm", "version": "11.2.3", "onFail": "error"})
	not dev_engines_flagged({"name": "pnpm", "version": "11.2.3", "onFail": "download"})
	not dev_engines_flagged([{"name": "pnpm", "version": "11.2.3", "onFail": "error"}])
}

test_dev_engines_on_fail_rejects_unsafe_values if {
	dev_engines_flagged({"name": "pnpm", "version": "11.2.3", "onFail": "ignore"})
	dev_engines_flagged({"name": "pnpm", "version": "11.2.3", "onFail": "warn"})
	dev_engines_flagged({"name": "pnpm", "version": "^11.0.0", "onFail": "download"})
	dev_engines_flagged({"name": "pnpm", "version": "11.1.2", "onFail": "download"})
	dev_engines_flagged([{"name": "pnpm", "version": "11.2.3", "onFail": "ignore"}])
}

test_pm_on_fail_download_needs_a_pin_of_the_minimum_version if {
	pm_on_fail_flagged({"devEngines": {"packageManager": {"name": "pnpm", "version": "11.1.2"}}}, "download")
	not pm_on_fail_flagged({"devEngines": {"packageManager": {"name": "pnpm", "version": "11.1.3"}}}, "download")
}

ci_command(command) := {"path": "Dockerfile", "projectRoot": ".", "command": command, "env": {"CI": "true"}}

npm_project := object.union(pnpm_project, {"manager": "npm", "lockfilePath": "package-lock.json"})

npm_settings := {
	"engine-strict": "true",
	"allow-git": "root",
	"allow-remote": "root",
	"ignore-scripts": "true",
	"min-release-age": "7",
}

test_npm_project_with_its_own_npmrc_is_accepted if {
	project := object.union(npm_project, {"package": {"engines": {"npm": ">=11.10.0"}}, "npmrc": npm_settings})
	findings := policies.deny with input as {"projects": [project]}
	count(findings) == 0
}

# npm reads only the .npmrc of the project it runs in, not one in a parent folder.
test_npmrc_is_required_next_to_every_npm_package if {
	inherited := object.union(npm_project, {
		"root": "app",
		"packagePath": "app/package.json",
		"package": {"engines": {"npm": ">=11.10.0"}},
		"npmrc": npm_settings,
	})
	findings := policies.deny with input as {"projects": [inherited]}
	some finding in findings
	finding.policy_id == "javascript/npmrc-required"
	finding._loc.file == "app/.npmrc"
}

test_npmrc_settings_are_checked_only_in_the_own_npmrc if {
	inherited := object.union(npm_project, {"root": "app", "packagePath": "app/package.json", "npmrc": {}})
	ids := finding_ids(policies.deny) with input as {"projects": [inherited]}
	"javascript/npmrc-required" in ids
	not "javascript/npmrc-min-release-age" in ids
	not "javascript/npmrc-engine-strict" in ids
}

test_prefer_pnpm_explains_unchecked_lockfiles if {
	findings := policies.warn with input as {"projects": [npm_project]}
	some finding in findings
	finding.policy_id == "javascript/prefer-pnpm"
	contains(finding.msg, "npm ci installs a locked version")
}

# One finding per problem: each pair below used to produce two findings.
test_inline_npm_install_is_reported_once if {
	ids := finding_ids(policies.deny) with input as {
		"projects": [npm_project],
		"ciCommands": [ci_command("npm install eslint")],
	}
	"javascript/inline-package-install" in ids
	not "javascript/npm-ci-required" in ids
}

test_npx_in_pnpm_project_is_reported_once if {
	ids := finding_ids(policies.deny) with input as {
		"projects": [pnpm_project],
		"ciCommands": [ci_command("npx prettier --check .")],
	}
	"javascript/inline-package-install" in ids
	not "javascript/npm-command-in-pnpm-ci" in ids
}

test_npm_install_in_pnpm_project_is_reported_once if {
	ids := finding_ids(policies.deny) with input as {
		"projects": [pnpm_project],
		"ciCommands": [ci_command("npm install")],
	}
	"javascript/npm-command-in-pnpm-ci" in ids
	not "javascript/npm-ci-required" in ids
}

test_npm_install_in_npm_project_is_still_reported if {
	ids := finding_ids(policies.deny) with input as {
		"projects": [npm_project],
		"ciCommands": [ci_command("npm install")],
	}
	"javascript/npm-ci-required" in ids
}

test_npx_script_in_pnpm_project_is_reported_once if {
	project := object.union(pnpm_project, {"package": {"scripts": {"lint": "npx eslint ."}}})
	ids := finding_ids(policies.deny) with input as {"projects": [project]}
	"javascript/inline-package-install-script" in ids
	not "javascript/npm-command-in-pnpm-script" in ids
}

test_unsupported_manager_is_reported_without_lockfile_finding if {
	project := object.union(pnpm_project, {"manager": "yarn", "lockfilePath": ""})
	ids := finding_ids(policies.deny) with input as {"projects": [project]}
	"javascript/supported-package-manager" in ids
	not "javascript/lockfile-required" in ids
}

test_pnpm_package_manager_field_is_rejected if {
	project := object.union(pnpm_project, {"package": {"packageManager": "pnpm@11.2.3"}})
	ids := finding_ids(policies.deny) with input as {"projects": [project]}
	"javascript/pnpm-package-manager-field" in ids
}

test_pnpm_dev_engines_pin_without_package_manager_is_accepted if {
	ids := finding_ids(policies.deny) with input as {"projects": [object.union(pnpm_project, {"package": dev_engines_pnpm})]}
	not "javascript/pnpm-package-manager-field" in ids
}

container_command(command) := {"path": "Dockerfile", "projectRoot": ".", "command": command, "env": {"CI": "true"}}

container_ids(command) := ids if {
	ids := finding_ids(policies.deny) with input as {
		"projects": [pnpm_project],
		"ciCommands": [container_command(command)],
		"containerBuilds": [{"path": "Dockerfile", "projectRoot": ".", "copiedFiles": ["pnpm-lock.yaml"]}],
	}
}

ci_command_rules := {
	"javascript/inline-package-install",
	"javascript/npm-ci-required",
	"javascript/npm-command-in-pnpm-ci",
	"javascript/unsupported-ci-package-manager",
	"javascript/pnpm-ci-environment",
}

test_container_may_install_an_allowed_pnpm_globally if {
	every command in {
		"npm install -g pnpm@12.13.0",
		"npm i -g pnpm@11.1.3",
		"npm install --global pnpm@12.15.0",
		"npm install pnpm@12.13.0 -g",
		"npm install -g pnpm@12.13.0 && pnpm install --frozen-lockfile",
		"npm i --global pnpm@12.13.0     && pnpm --version",
	} {
		count(container_ids(command) & ci_command_rules) == 0
	}
}

test_container_global_pnpm_install_needs_an_allowed_exact_version if {
	every command in {
		"npm install -g pnpm",
		"npm install -g pnpm@latest",
		"npm install -g pnpm@12",
		"npm install -g pnpm@^12.0.0",
		"npm install -g pnpm@10.30.0",
		"npm install -g pnpm@11.1.2",
		"npm install -g pnpm@12.0.0-rc.1",
	} {
		"javascript/inline-package-install" in container_ids(command)
	}
}

test_container_global_pnpm_install_does_not_hide_other_packages if {
	every command in {
		"npm install -g pnpm@12.13.0 eslint",
		"npm install -g pnpm@12.13.0 && npx eslint .",
		"npm install -g pnpm@12.13.0; npm install -g eslint",
	} {
		"javascript/inline-package-install" in container_ids(command)
	}
}

test_container_global_pnpm_install_does_not_hide_npm_install if {
	"javascript/npm-command-in-pnpm-ci" in container_ids("npm install -g pnpm@12.13.0 && npm install")
}

# The exception only covers container builds, not GitHub workflows.
test_workflow_global_pnpm_install_is_still_reported if {
	ids := finding_ids(policies.deny) with input as {
		"projects": [pnpm_project],
		"githubDocuments": [{"path": ".github/workflows/ci.yml", "document": {}}],
		"ciCommands": [{"path": ".github/workflows/ci.yml", "projectRoot": ".", "command": "npm install -g pnpm@12.13.0", "env": {}}],
	}
	"javascript/inline-package-install" in ids
}

# A package that pins pnpm in devEngines may set engines.npm to a minimum of 10.9.0 instead of
# disallow, so consumers of a published package can still install it with npm.
engines_findings(package_document) := {id |
	project := object.union(pnpm_project, {"package": package_document})
	some id in finding_ids(policies.deny) with input as {"projects": [project]}
	id in {"javascript/pnpm-disallow-npm", "javascript/minimum-pnpm-version"}
}

dev_engines_with_engines(engines) := object.union(dev_engines_pnpm, {"engines": engines})

test_dev_engines_pin_allows_an_npm_minimum_instead_of_disallow if {
	count(engines_findings(dev_engines_with_engines({"npm": ">=10.9.0", "pnpm": ">=11.1.3"}))) == 0
	count(engines_findings(dev_engines_with_engines({"npm": ">=11.10.0", "pnpm": ">=12.0.0"}))) == 0
	count(engines_findings(dev_engines_with_engines({"npm": "disallow", "pnpm": ">=11.1.3"}))) == 0
}

# npm 7 to 10.8 and pnpm 9 and 10 ignore devEngines.packageManager, and run on any Node.js,
# so engines.node does not keep them out.
test_dev_engines_pin_with_engines_node_alone_is_rejected if {
	engines_findings(dev_engines_with_engines({"node": ">=22.10.0"})) == {
		"javascript/pnpm-disallow-npm",
		"javascript/minimum-pnpm-version",
	}
}

# pnpm 10 and older ignore devEngines.packageManager.
test_dev_engines_pin_does_not_replace_engines_pnpm if {
	engines_findings(dev_engines_with_engines({"npm": ">=10.9.0"})) == {"javascript/minimum-pnpm-version"}
}

test_npm_minimum_instead_of_disallow_needs_npm_10_9 if {
	"javascript/pnpm-disallow-npm" in engines_findings(dev_engines_with_engines({"npm": ">=10.8.0", "pnpm": ">=11.1.3"}))
	"javascript/pnpm-disallow-npm" in engines_findings(dev_engines_with_engines({"npm": "*", "pnpm": ">=11.1.3"}))
}

test_npm_minimum_instead_of_disallow_needs_an_exact_pnpm_pin if {
	# Without devEngines, nothing stops npm 10.9 and newer.
	engines_findings({"engines": {"npm": ">=10.9.0", "pnpm": ">=11.1.3"}}) == {"javascript/pnpm-disallow-npm"}

	# A range does not pin pnpm.
	"javascript/pnpm-disallow-npm" in engines_findings({
		"engines": {"npm": ">=10.9.0", "pnpm": ">=11.1.3"},
		"devEngines": {"packageManager": {"name": "pnpm", "version": "^11.1.3"}},
	})

	# A pin older than 11.1.3 installs lockfiles that pin versions younger than minimumReleaseAge.
	"javascript/pnpm-disallow-npm" in engines_findings({
		"engines": {"npm": ">=10.9.0", "pnpm": ">=11.1.3"},
		"devEngines": {"packageManager": {"name": "pnpm", "version": "11.1.2"}},
	})
}

test_engines_still_required_without_dev_engines if {
	engines_findings({}) == {"javascript/pnpm-disallow-npm", "javascript/minimum-pnpm-version"}
}
