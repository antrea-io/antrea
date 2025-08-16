#!/bin/bash
set -euo pipefail

branch_name="$1"

if [[ ! "$branch_name" =~ ^release-2\.([0-9]+)$ ]]; then
    echo "Error: branch name must be in format release-2.X where X is a number"
    exit 1
fi

suffix="${BASH_REMATCH[1]}"

# Calculate previous two suffixes
prev1=$((suffix - 1))
prev2=$((suffix - 2))

# Construct previous branch names, only if prev1 and prev2 >= 0
branches=("main" "$branch_name")
if (( prev1 >= 0 )); then
    branches+=("release-2.$prev1")
fi
if (( prev2 >= 0 )); then
    branches+=("release-2.$prev2")
fi

branches_str=$(printf '"%s", ' "${branches[@]}")
branches_str="[${branches_str%,}]"  # remove trailing comma and add brackets

replacement="  baseBranches: $branches_str,"

file="../.github/renovate.json5"

sed -i.bak -E "s|^\s*baseBranches:.*|$replacement|" "$file"
