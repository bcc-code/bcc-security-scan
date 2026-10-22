package supply_chain.policies

import rego.v1

# Every rule below follows the same shape as javascript.rego.

# Requires external actions and reusable workflows to be pinned to a full commit SHA,
# because tags and branches can be moved to point at different code.
# The check action groups findings by this message's ending; keep it unchanged.
deny contains finding if {
	some document in input.githubDocuments
	some reference in action_references(document.document)
	not is_local_reference(reference)
	not is_docker_reference(reference)
	not reference in github_pin_exceptions
	not is_commit_sha_pin(reference)

	finding := policy_finding(
		sprintf("%q must use a full 40-character commit SHA", [reference]),
		document.path,
		"github-actions/full-commit-sha",
	)
}

# Requires Docker actions to be pinned to an image digest,
# because image tags can be moved to point at a different image.
deny contains finding if {
	some document in input.githubDocuments
	some reference in action_references(document.document)
	is_docker_reference(reference)
	not is_image_digest_pin(reference)

	finding := policy_finding(
		sprintf("%q must use an immutable sha256 image digest", [reference]),
		document.path,
		"github-actions/docker-image-digest",
	)
}
