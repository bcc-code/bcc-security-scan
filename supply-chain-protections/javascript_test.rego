package supply_chain_tests.javascript_test

import rego.v1
import data.supply_chain.policies

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

hash_pinned_pnpm := "pnpm@11.2.3+sha512.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

pm_on_fail_flagged(package_document, pm_on_fail) if {
    project := object.union(pnpm_project, {"package": package_document, "workspace": {"pmOnFail": pm_on_fail}})
    findings := policies.deny with input as {"projects": [project]}
    "javascript/pnpm-workspace-pm-on-fail" in finding_ids(findings)
}

test_pm_on_fail_error_is_allowed if {
    not pm_on_fail_flagged({}, "error")
}

test_pm_on_fail_download_is_allowed_with_hash_pinned_package_manager if {
    not pm_on_fail_flagged({"packageManager": hash_pinned_pnpm}, "download")
}

test_pm_on_fail_download_is_rejected_without_hash_pin if {
    every package_document in [
        {},
        {"packageManager": "pnpm@11.2.3"},
        {"packageManager": "pnpm@10.30.0+sha512.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    ] {
        pm_on_fail_flagged(package_document, "download")
    }
}

test_pm_on_fail_other_values_are_rejected if {
    every value in ["", "warn", "ignore"] {
        pm_on_fail_flagged({"packageManager": hash_pinned_pnpm}, value)
    }
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
