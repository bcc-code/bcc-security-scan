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