#!/usr/bin/env bash

# Copyright 2020 Antrea Authors
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

# This script is inspired by the one maintained in
# https://github.com/kubernetes/enhancements

set -o errexit
set -o nounset
set -o pipefail

TOOL_VERSION=$(head hack/mdtoc-version)

GO_VERSION="$(${GO} version | awk '{print $3}')"
function version_lt() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" != "$1"; }

if version_lt "${GO_VERSION}" "go1.16"; then
    # See https://golang.org/doc/go-get-install-deprecation
    echo "Running this script requires Go >= 1.16, please upgrade"
    exit 1
fi

# cd to the root path
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

# create a temporary directory
TMP_DIR=$(mktemp -d)

# cleanup
exitHandler() (
  echo "Cleaning up temporary directory"
  rm -rf "${TMP_DIR}"
)
trap exitHandler EXIT

GOBIN="${TMP_DIR}" ${GO} install "github.com/tallclair/mdtoc@${TOOL_VERSION}"
export PATH="${TMP_DIR}:${PATH}"

echo "Checking table of contents are up to date..."
# Verify tables of contents are up-to-date
find docs -name '*.md' | grep -Fxvf hack/.notableofcontents | xargs mdtoc --inplace --dryrun
mdtoc --inplace --dryrun CONTRIBUTING.md
