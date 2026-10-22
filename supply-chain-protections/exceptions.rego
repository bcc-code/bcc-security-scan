package supply_chain.policies

import rego.v1

# Exceptions to the policy, kept apart from the rules so they are easy to review.
# This is a Rego file, not JSON or YAML, because the check action passes this
# folder to Conftest as --policy, and Conftest only loads data files given with --data.

# Reusable workflows allowed without a full commit SHA.
# Infra Platform reusable workflows are trusted to track their main branch.
github_pin_exceptions := {
	"bcc-code/bcc-platform-deploy/.github/workflows/landing-zone.yml@main",
	"bcc-code/bcc-platform-deploy/.github/workflows/terraform.yml@main",
}
