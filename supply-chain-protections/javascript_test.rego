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
	dev_engines_flagged([{"name": "pnpm", "version": "11.2.3", "onFail": "ignore"}])
}

ci_command(command) := {"path": "Dockerfile", "projectRoot": ".", "command": command, "env": {"CI": "true"}}

npm_project := object.union(pnpm_project, {"manager": "npm", "lockfilePath": "package-lock.json"})

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
