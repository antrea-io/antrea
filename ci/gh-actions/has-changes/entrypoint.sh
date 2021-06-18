#!/usr/bin/env bash

set -eo pipefail

read -r -a PATTERNS <<< "$*"

cat "$GITHUB_EVENT_PATH"

PR_BASE_SHA=$(jq -r '.pull_request.base.sha' "$GITHUB_EVENT_PATH")
BEFORE=$(jq -r '.before' "$GITHUB_EVENT_PATH")
if [[ $PR_BASE_SHA != "" && $PR_BASE_SHA != "null" ]]; then # PR events
    SHA=$PR_BASE_SHA
elif [[ $BEFORE != "" && $BEFORE != "null" ]]; then # push events
    SHA=$BEFORE
else
    echo "This does not appear to be a PR or a push event"
    echo "Setting 'has_changes' to 'yes'"
    echo "::set-output name=has_changes::yes"
    exit 0
fi
echo "BASE SHA: $SHA"

CHANGED_FILES=$(git diff --name-only "$SHA" HEAD) || rc=$?

if [[ $rc -ne 0 ]]; then
    echo "Error when running 'git diff'"
    echo "This is expected when the repo was not checked-out properly, or after a force push"
    echo "Setting 'has_changes' to 'yes'"
    echo "::set-output name=has_changes::yes"
    exit 0
fi

echo "CHANGED_FILES are:"
echo "$CHANGED_FILES"

has_changes=false
for changed_file in $CHANGED_FILES; do
    matched=false
    for pattern in "${PATTERNS[@]}"; do
        if [[ "$changed_file" == $pattern ]]; then
            matched=true
            break
        fi
    done
    if ! $matched; then
        has_changes=true
        break
    fi
done

if $has_changes; then
    echo "Setting 'has_changes' to 'yes'"
    echo "::set-output name=has_changes::yes"
else
    echo "Setting 'has_changes' to 'no'"
    echo "::set-output name=has_changes::no"
fi
