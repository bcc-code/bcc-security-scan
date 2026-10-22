package supply_chain_tests.policies_test

import data.supply_chain.policies
import rego.v1

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

test_dev_engines_pinned_at_least_requires_exact_version if {
	policies.dev_engines_pinned_at_least(
		{"devEngines": {"packageManager": {"name": "pnpm", "version": "11.2.3"}}},
		"pnpm",
		"11.0.0",
	)
	every package_document in [
		{},
		{"packageManager": "pnpm@11.2.3"},
		{"devEngines": {"packageManager": {"name": "pnpm", "version": "^11.0.0"}}},
		{"devEngines": {"packageManager": {"name": "pnpm", "version": "11"}}},
		{"devEngines": {"packageManager": {"name": "pnpm", "version": "10.30.0"}}},
		{"devEngines": {"packageManager": {"name": "npm", "version": "11.10.0"}}},
		{"devEngines": {"packageManager": [{"name": "pnpm", "version": "11.2.3"}]}},
	] {
		not policies.dev_engines_pinned_at_least(package_document, "pnpm", "11.0.0")
	}
}

test_directory_of if {
	policies.directory_of("pnpm-workspace.yaml") == "."
	policies.directory_of("apps/web/pnpm-workspace.yaml") == "apps/web"
}

test_is_workspace_root if {
	policies.is_workspace_root({"root": ".", "workspacePath": "pnpm-workspace.yaml"})
	policies.is_workspace_root({"root": "apps/web", "workspacePath": "apps/web/pnpm-workspace.yaml"})
	policies.is_workspace_root({"root": "solo", "workspacePath": ""})
	not policies.is_workspace_root({"root": "apps/web", "workspacePath": "pnpm-workspace.yaml"})
}
