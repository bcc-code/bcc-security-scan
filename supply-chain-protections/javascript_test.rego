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
