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
    not is_pin_exception(reference)
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

# ===========================================================================
# Disabled rules
# ===========================================================================

# Token permission rules, kept for when an approved-writes list exists.
#
# approved_write(path, job, scope) if {
#     scope in data.supply_chain.approved_writes[path][job]
# }
#
# # Requires workflows to declare scoped top-level permissions for the GitHub token.
# deny contains msg if {
#     some workflow in input.githubDocuments
#     startswith(workflow.path, ".github/workflows/")
#     permissions := object.get(workflow.document, "permissions", null)
#     not is_object(permissions)
#     msg := sprintf("%s must declare scoped top-level permissions", [workflow.path])
# }
#
# # Prevents unapproved write access in top-level GitHub token permissions.
# deny contains msg if {
#     some workflow in input.githubDocuments
#     permissions := object.get(workflow.document, "permissions", {})
#     is_object(permissions)
#     some scope, level in permissions
#     level == "write"
#     not approved_write(workflow.path, "*", scope)
#     msg := sprintf("%s has unapproved workflow permission %s: write", [
#         workflow.path,
#         scope,
#     ])
# }
#
# # Requires each job to use explicitly scoped GitHub token permissions.
# deny contains msg if {
#     some workflow in input.githubDocuments
#     some job_name, job in object.get(workflow.document, "jobs", {})
#     permissions := object.get(job, "permissions", {})
#     not is_object(permissions)
#     msg := sprintf("%s job %s uses unscoped permissions", [
#         workflow.path,
#         job_name,
#     ])
# }
#
# # Prevents unapproved write access in job-level GitHub token permissions.
# deny contains msg if {
#     some workflow in input.githubDocuments
#     some job_name, job in object.get(workflow.document, "jobs", {})
#     permissions := object.get(job, "permissions", {})
#     is_object(permissions)
#     some scope, level in permissions
#     level == "write"
#     not approved_write(workflow.path, job_name, scope)
#     msg := sprintf("%s job %s has unapproved permission %s: write", [
#         workflow.path,
#         job_name,
#         scope,
#     ])
# }
