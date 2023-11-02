#!/usr/bin/env bash

# Copyright 2022 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 --release <RELEASE> [--from-release <RELEASE>] [--all]
Draft the changelog for a release based on PR history starting from the last release.
For a minor release such as 1.5.0, the changelog will base on PRs merged to main branch since the fork of release-1.4.
For a patch release such as 1.5.2, the changelog will base on PRs merged to release-1.5 branch since the release of 1.5.1.

Options:
        --release <RELEASE>        The release for which the changelog is generated
        --from-release <RELEASE>   The last release from which the changelog is generated. It's supposed to be used only
                                   when running the script for a major release such as 2.0.0
        --all                      Include PRs that are not labelled with 'action/release-note' in a separate section"

function print_usage {
  echoerr "$_usage"
}

if ! command -v gh > /dev/null; then
  echoerr "Can't find 'gh' tool in PATH, please install from https://github.com/cli/cli"
  exit 1
fi

release=""
from_release=""
all="no"
limit=500
# PRs authored by them will not be collected in Unlabelled section.
ignored_authors=("app/dependabot" "antrea-bot")
# Disable the pager of gh command to print the output to stdout.
export PAGER=""

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
  --release)
  release="$2"
  shift 2
  ;;
  --from-release)
  from_release="$2"
  shift 2
  ;;
  --all)
  all="yes"
  shift
  ;;
  -h|--help)
  print_usage
  exit 0
  ;;
  *)    # unknown option
  echoerr "Unknown option $1"
  exit 1
  ;;
esac
done

if [ "$release" == "" ]; then
  echoerr "--release must be set"
  exit 1
fi

major_minor_number="${release%.*}"
major_number="${major_minor_number%.*}"
minor_number="${major_minor_number#*.}"
patch_number="${release##*.}"

if [ "$from_release" == "" ]; then
  if [ "$patch_number" == "0" ]; then
    from_release="${major_number}.$(( minor_number-1 )).0"
  else
    from_release="${major_number}.${minor_number}.$(( patch_number-1 ))"
  fi
fi

# For minor releases, PRs are merged to main branch.
# For patch releases, PRs are merged to release branches.
branch="main"
if [ "$patch_number" != "0" ]; then
  branch="release-${major_minor_number}"
fi

# Get the best common ancestor between the current branch and the last release.
common_ancestor=$(git merge-base "v${from_release}" "upstream/${branch}")
# Get the merge time of the common ancestor and use it as the start time of the current release.
release_start_time=$(gh pr list --state merged --search "${common_ancestor}" --json mergedAt -q .[0].mergedAt)

# Do not generate the title for patch releases.
if [ "$patch_number" == "0" ]; then
  echo "# Changelog ${major_minor_number}"
  echo ""
fi
echo "## ${release} - $(date +%F)"
echo ""
echo "### Added"
echo ""

echo "### Changed"
echo ""

authors=()
# Put the changes under "Changed" first, release manager needs to move them to appropriate sections manually.
gh pr list -s merged -B ${branch} --search "merged:>${release_start_time} sort:updated-desc label:action/release-note" -L $limit --json number,title,author,labels --template \
'{{range .}}{{tablerow (printf "- %s. ([#%v](https://github.com/antrea-io/antrea/pull/%v), [@%s])" .title .number .number .author.login)}}{{end}}'

while read -r author; do
  authors+=("$author")
done < <(gh pr list -s merged -B ${branch} --search "merged:>${release_start_time} sort:updated-desc label:action/release-note" -L $limit --json author --jq .[].author.login)

if [ "$patch_number" != "0" ]; then
  regexp_title="^Cherry pick of (#[[:digit:]]+[[:space:]]*)+ on release"
  regexp_number="#([[:digit:]]+)"
  while read -r line; do
    if [[ ${line} =~ ${regexp_title} ]]; then
      while [[ ${line} =~ ${regexp_number} ]]; do
        gh pr view ${BASH_REMATCH[1]} --json number,title,author,labels --template \
        '{{(printf "- %s. ([#%v](https://github.com/antrea-io/antrea/pull/%v), [@%s])\n" $.title $.number $.number $.author.login)}}'
        line=${line#*"${BASH_REMATCH[1]}"}
        author=$(gh pr view ${BASH_REMATCH[1]} --json author --template '{{(printf "%s" $.author.login)}}')
        authors+=("$author")
      done
    fi
  done < <(gh pr list -s merged -B ${branch} --search "merged:>${release_start_time} sort:updated-desc label:kind/cherry-pick" -L $limit --json body --template '{{range .}}{{printf "%s\n" .body}}{{end}}')
fi

echo ""

echo "### Fixed"
echo ""

if [ "$all" == "yes" ]; then
  author_filter=""
  for author in "${ignored_authors[@]}"; do
    author_filter="${author_filter} -author:${author}"
  done
  # There may be some changes not being labelled properly, release manager needs to move them to appropriate sections manually.
  echo "### Unlabelled (Remove this section eventually)"
  echo ""
  gh pr list -s merged -B ${branch} --search "merged:>${release_start_time} sort:updated-desc -label:action/release-note -label:kind/cherry-pick $author_filter" -L $limit --json number,title,author,labels --template \
  '{{range .}}{{tablerow (printf "- %s. ([#%v](https://github.com/antrea-io/antrea/pull/%v), [@%s])" .title .number .number .author.login)}}{{end}}'
fi

echo ""
echo ""

# sort, deduplicate the authors and print the links to GitHub profiles.
printf "%s\n" "${authors[@]}" | sort -u | while read -r author; do
  echo "[@${author}]: https://github.com/${author}"
done
