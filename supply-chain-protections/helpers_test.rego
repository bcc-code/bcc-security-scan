package supply_chain_tests.policies_test

import rego.v1
import data.supply_chain.policies

test_uses_npm_detects_npx if {
    policies.uses_npm("npx eslint .")
}

test_inline_package_execution_is_detected if {
    every command in {
        "npx eslint .",
        "npm exec eslint .",
        "npm x eslint .",
        "pnpm dlx eslint .",
        "pnpx eslint .",
        "yarn dlx eslint .",
        "bunx eslint .",
        "bun x eslint .",
    } {
        policies.uses_inline_install(command)
    }
}

test_inline_package_addition_is_detected if {
    every command in {
        "npm install eslint",
        "pnpm add eslint",
        "yarn add eslint",
        "bun add eslint",
        "deno add npm:eslint",
        "yarn global add eslint",
        "pnpm install --save-dev eslint",
    } {
        policies.uses_inline_install(command)
    }
}

test_lockfile_install_is_not_inline if {
    not policies.uses_inline_install("pnpm install --frozen-lockfile")
}

test_engine_at_least_accepts_safe_ranges if {
    every constraint in {
        ">=11.10.0",
        "^11.10.0 || 12.x",
        ">=11.10.0 <12.0.0 || >=12",
        "<13.0.0 >=11.10.0",
        ">=9.0.0 >=11.10.0 <12.0.0",
        "11.10.0 - 12.0.0",
        "^11.10.0 || 11.29.x || 12.x.x || 11.11.0 - 11.12.90 || 11.10.0",
    } {
        policies.engine_at_least(constraint, "11.10.0")
    }
}

test_engine_at_least_rejects_range_with_old_versions if {
    not policies.engine_at_least(
        "^9.0.0 || 8.29.x || 9.0.0 - 10.0.0 || 10.10.0",
        "11.10.0",
    )
}

test_engine_at_least_rejects_unsafe_ranges if {
    every constraint in {
        ">=11.0.0 <12.0.0",
        "<12.0.0",
        "9.0.0 - 12.0.0",
        "*",
    } {
        not policies.engine_at_least(constraint, "11.10.0")
    }
}
test_pnpm_declared_version_accepts_safe_declarations if {
    every manifest in [
        {"packageManager": "pnpm@11.0.0"},
        {"packageManager": "pnpm@11.2.1+sha512.abc123"},
        {"devEngines": {"packageManager": {"name": "pnpm", "version": "^11.0.0"}}},
        {"devEngines": {"packageManager": [{"name": "pnpm", "version": ">=11.1.0"}]}},
        {
            "packageManager": "pnpm@11.0.0",
            "devEngines": {"packageManager": {"name": "pnpm", "version": "^11.0.0"}},
        },
    ] {
        policies.pnpm_declared_version_at_least(manifest, "11.0.0")
    }
}

test_pnpm_declared_version_rejects_missing_or_old_declarations if {
    every manifest in [
        {},
        {"packageManager": "pnpm@10.12.1"},
        {"packageManager": "npm@11.10.0"},
        {"packageManager": "pnpm@latest"},
        {"devEngines": {"packageManager": {"name": "pnpm", "version": "^10.0.0 || ^11.0.0"}}},
        {"devEngines": {"packageManager": {"name": "npm", "version": ">=11.10.0"}}},
        {
            "packageManager": "pnpm@11.0.0",
            "devEngines": {"packageManager": {"name": "pnpm", "version": "^10.0.0"}},
        },
    ] {
        not policies.pnpm_declared_version_at_least(manifest, "11.0.0")
    }
}

pnpm_download_project(manifest) := {
    "manager": "pnpm",
    "workspacePath": "pnpm-workspace.yaml",
    "workspace": {"pmOnFail": "download"},
    "packagePath": "manifest.json",
    "package": manifest,
}

pnpm_download_denied(manifest) if {
    some finding in policies.deny with input as {"projects": [pnpm_download_project(manifest)]}
    finding.policy_id == "javascript/pnpm-download-version"
}

test_pnpm_download_requires_declared_version if {
    pnpm_download_denied({})
    pnpm_download_denied({"packageManager": "pnpm@10.12.1"})
    not pnpm_download_denied({"packageManager": "pnpm@11.0.0"})
}

test_pnpm_error_does_not_require_declared_version if {
    project := object.union(pnpm_download_project({}), {"workspace": {"pmOnFail": "error"}})
    findings := policies.deny with input as {"projects": [project]}
    every finding in findings {
        finding.policy_id != "javascript/pnpm-download-version"
    }
}
