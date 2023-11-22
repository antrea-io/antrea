#!/usr/bin/env bash

# Copyright 2023 Antrea Authors
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

_usage="Usage: $0 --release <RELEASE> [--latest]
Draft the release in Github.

Examples:
  $0 --release 1.14.0 --latest      # Draft a release for v1.14.0 and force mark it as the latest release.
  $0 --release 1.13.2               # Draft a release for v1.13.2 and mark it as the latest release based on date and version.

Options:
        --release <RELEASE>        The release to generate.
        --latest                   Mark this release as \"Latest\" (default: automatic based on date and version)."

function print_usage {
  echoerr "$_usage"
}

if ! command -v gh > /dev/null; then
  echoerr "Can't find 'gh' tool in PATH, please install from https://github.com/cli/cli"
  exit 1
fi

repo="antrea-io/antrea"
release=""
latest="no"

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
  --release)
  release="$2"
  shift 2
  ;;
  --latest)
  latest="yes"
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

if [[ ! "$release" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echoerr "release must follow semantic versioning, e.g. v1.13.2, 1.14.0"
  exit 1
fi

# Remove the first "v" if there is one.
release="${release#v}"

major_minor_number="${release%.*}"
branch="release-${major_minor_number}"
tag="v${release}"
project="${repo##*/}"
title="${project^} $tag"
changelog_url="https://github.com/$repo/raw/$branch/CHANGELOG/CHANGELOG-${major_minor_number}.md"

echo "+++ Downloading changelog..."
# Get the changelog and make it github friendly.
# In particular, we remove links for authors to make github include a "Contributors" section with an avatar list of all
# the mentioned authors.
changelog=$(curl -sL "$changelog_url" |
  awk "/## ${release}/{ p = 1; next } /## [0-9]/{ p = 0 } p" | # Get the section of the target release.
  awk 'NF {p=1} p' |            # Exclude the first blank line.
  sed '/^\[@.*\]:/d' |          # Delete the author links.
  sed 's/\[\(@[^]]*\)\]/\1/g')  # Delete the square brackets of author names.

if [ -z "$changelog" ]; then
  echoerr "changelog is empty, has the changelog of $tag been committed?"
  exit 1
fi

echo "+++ Please review the following release information:"
echo "Title:  $title"
echo "Repo:   $repo"
echo "Branch: $branch"
echo "Tag:    $tag"
echo "Notes:"
echo "$changelog"
echo
echo "+++ I'm about to create a release draft on GitHub with the above information."
read -p "+++ Proceed (anything but 'y' aborts the release)? [y/n] " -r
if ! [[ "${REPLY}" =~ ^[yY]$ ]]; then
  echo "Aborting." >&2
  exit 1
fi

args=""

if [ "$latest" == "yes" ]; then
  args="${args} --latest"
fi

url=$(gh release create "$tag" --draft --repo "$repo" --target "$branch" --title "$title" --notes "$changelog" $args)

echo "+++ Release draft has been created."
echo "+++ To proceed to the release, open the URL:"
echo ""
echo "$url"
