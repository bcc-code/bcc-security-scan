#!/usr/bin/env bash
# Checks one setup's fixtures against the policy on a branch other than policy-v1,
# for example an unmerged policy pull request. supply-chain-protections/check always
# downloads policy-v1, so this does what it does with another branch: run the
# inventory action, then the same Conftest version on that branch's
# supply-chain-protections folder. It writes the same result file as the workflow's
# "Record the result" step.
#
# Usage: testing/policy-check.sh <policy-branch> <setup> <accept|reject> <fixtures-dir> <results-dir>
# Run it from the repository root.

set -euo pipefail

ref=$1
setup=$2
expected=$3
fixtures=$4
results=$5
repository="${GITHUB_REPOSITORY:-bcc-code/bcc-security-scan}"
work="${RUNNER_TEMP:-/tmp}/policy-check-$setup"

rm -rf "$work"
mkdir -p "$work/policy" "$results"

# The same Conftest version and checksum as supply-chain-protections/check.
conftest_version=0.69.0
conftest_sha256=96fc2fbf11f0afde51256647127e6f00a64ce839a4d9a0a1aef2426c0e6f4b3f
curl --fail --location --silent --show-error \
  "https://github.com/open-policy-agent/conftest/releases/download/v${conftest_version}/conftest_${conftest_version}_Linux_x86_64.tar.gz" \
  --output "$work/conftest.tar.gz"
if ! printf '%s  %s\n' "$conftest_sha256" "$work/conftest.tar.gz" | sha256sum --check --status -; then
  echo "::error::Conftest checksum verification failed"
  exit 1
fi
tar -xzf "$work/conftest.tar.gz" -C "$work" conftest

curl --fail --location --silent --show-error \
  "https://github.com/$repository/archive/refs/heads/$ref.tar.gz" |
  tar -xz -C "$work/policy" --strip-components=2 --wildcards '*/supply-chain-protections/*'

declare -A exit_code messages
for variant in mature fresh; do
  inventory="$work/$variant-inventory.json"
  : > "$work/github-output"
  INPUT_ROOT="$fixtures/$setup/$variant" \
    INPUT_OUTPUT="$inventory" \
    INPUT_REPOSITORY="$repository" \
    GITHUB_OUTPUT="$work/github-output" \
    node supply-chain-protections/inventory/dist/index.js

  set +e
  "$work/conftest" test "$inventory" \
    --policy "$work/policy" \
    --namespace "supply_chain.*" \
    --output sarif \
    --show-builtin-errors > "$work/$variant.sarif"
  exit_code[$variant]=$?
  set -e

  messages[$variant]="$(jq -c \
    '[.runs[].results[] | select(.level == "error") | .message.text]' \
    "$work/$variant.sarif" 2>/dev/null || echo '[]')"
done

jq -n \
  --arg setup "$setup" \
  --arg expected "$expected" \
  --arg policy "$ref" \
  --arg mature_exit "${exit_code[mature]}" \
  --argjson mature_messages "${messages[mature]}" \
  --arg fresh_exit "${exit_code[fresh]}" \
  --argjson fresh_messages "${messages[fresh]}" \
  '{
    setup: $setup,
    expected: $expected,
    policy: $policy,
    mature: {outcome: "success", exitCode: $mature_exit, messages: $mature_messages},
    fresh: {outcome: "success", exitCode: $fresh_exit, messages: $fresh_messages}
  }' > "$results/$setup.json"
cat "$results/$setup.json"

accepted=false
if [[ "${exit_code[mature]}" == "0" && "${exit_code[fresh]}" == "0" ]]; then
  accepted=true
fi
if [[ "$expected" == "accept" && "$accepted" != "true" ]]; then
  echo "::error::The $ref policy does not accept the $setup fixtures, so its test results do not describe an accepted setup."
elif [[ "$expected" == "reject" && "$accepted" == "true" ]]; then
  echo "::error::The $ref policy accepts the $setup fixtures, but must reject them."
fi
