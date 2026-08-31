package supply_chain.policies

import rego.v1

# Requires workflows to declare scoped top-level permissions for the GitHub token.
# deny contains msg if {
#     some workflow in input.githubDocuments
#     startswith(workflow.path, ".github/workflows/")
#     permissions := object.get(workflow.document, "permissions", null)
#     not is_object(permissions)
#     msg := sprintf("%s must declare scoped top-level permissions", [workflow.path])
# }

# Prevents unapproved write access in top-level GitHub token permissions.
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

# Requires each job to use explicitly scoped GitHub token permissions.
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

# Prevents unapproved write access in job-level GitHub token permissions.
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

# Pins external GitHub Actions and any reusable workflows to immutable full commit SHAs.
# Infra Platform reusable workflows are excepted from this rule
deny contains finding if {
    some document in input.githubDocuments
    some _, node in walk(document.document)
    is_object(node)

    reference := object.get(node, "uses", "")
    reference != ""
    not is_local_reference(reference)
    not is_docker_reference(reference)
    not github_pin_exception(reference)
    not valid_github_pin(reference)

    finding := {
        "msg": sprintf("%q must use a full 40-character commit SHA", [reference]),
        "_loc": {
            "file": document.path,
            "line": 1,
        },
        "policy_id": "github-actions/full-commit-sha",
    }
}

# Pins Docker-based Actions to immutable SHA-256 image digests.
deny contains finding if {
    some document in input.githubDocuments
    some _, node in walk(document.document)
    is_object(node)

    reference := object.get(node, "uses", "")
    reference != ""
    is_docker_reference(reference)
    not valid_docker_pin(reference)

    finding := {
        "msg": sprintf("%q must use an immutable sha256 image digest", [reference]),
        "_loc": {
            "file": document.path,
            "line": 1,
        },
        "policy_id": "github-actions/docker-image-digest",
    }
}