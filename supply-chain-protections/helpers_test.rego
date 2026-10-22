package supply_chain_tests.policies_test

import rego.v1
import data.supply_chain.policies

test_runs_npm_detects_npx if {
    policies.runs_npm("npx eslint .")
}

test_runs_pnpm_detects_pnpm_commands if {
    every command in {
        "pnpm install --frozen-lockfile",
        "corepack enable && pnpm i",
        "cd app\npnpm build",
        "pnpm.cmd test",
    } {
        policies.runs_pnpm(command)
    }
}

test_runs_pnpm_ignores_other_commands if {
    every command in {
        "apt-get install -y curl",
        "echo pnpm-lock.yaml",
        "npm ci",
    } {
        not policies.runs_pnpm(command)
    }
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
        policies.runs_inline_package(command)
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
        policies.runs_inline_package(command)
    }
}

test_lockfile_install_is_not_inline if {
    not policies.runs_inline_package("pnpm install --frozen-lockfile")
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

test_package_manager_pinned_at_least_accepts_pinned_versions if {
    every value in {
        "pnpm@11.0.0",
        "pnpm@11.2.3",
        "pnpm@12.0.0+sha512.0123456789abcdef",
    } {
        policies.package_manager_pinned_at_least({"packageManager": value}, "pnpm", "11.0.0")
    }
}

test_package_manager_pinned_at_least_rejects_unproven_versions if {
    every package_document in [
        {},
        {"packageManager": "pnpm@10.30.0"},
        {"packageManager": "pnpm@11.0.0-rc.1"},
        {"packageManager": "pnpm@^11.0.0"},
        {"packageManager": "pnpm@11"},
        {"packageManager": "npm@11.10.0"},
        {"packageManager": "pnpm@11.0.0 "},
        {"packageManager": 11},
    ] {
        not policies.package_manager_pinned_at_least(package_document, "pnpm", "11.0.0")
    }
}

test_pnpm_version_proven_requires_package_manager_and_engines if {
    policies.pnpm_version_proven(
        {"packageManager": "pnpm@11.2.3", "engines": {"pnpm": ">=11.0.0"}},
        "11.0.0",
    )
    every package_document in [
        {"packageManager": "pnpm@11.2.3"},
        {"engines": {"pnpm": ">=11.0.0"}},
        {"packageManager": "pnpm@11.2.3", "engines": {"pnpm": ">=10.0.0"}},
        {"packageManager": "pnpm@10.30.0", "engines": {"pnpm": ">=11.0.0"}},
    ] {
        not policies.pnpm_version_proven(package_document, "11.0.0")
    }
}

test_is_true_accepts_booleans_and_strings if {
    every value in [true, "true", "TRUE"] {
        policies.is_true(value)
    }
    every value in [false, "false", "", 1, null] {
        not policies.is_true(value)
    }
}

test_action_references_finds_nested_uses if {
    document := {"jobs": {
        "build": {"steps": [{"uses": "actions/checkout@v4"}, {"run": "make"}]},
        "deploy": {"uses": "org/repo/.github/workflows/deploy.yml@main"},
    }}
    policies.action_references(document) == {
        "actions/checkout@v4",
        "org/repo/.github/workflows/deploy.yml@main",
    }
}
