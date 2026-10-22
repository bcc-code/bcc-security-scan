package supply_chain_tests.javascript_test

import rego.v1
import data.supply_chain.policies

pnpm_project := {
    "root": ".",
    "manager": "pnpm",
    "packagePath": "package.json",
    "package": {},
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
