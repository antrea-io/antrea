#!/usr/bin/env bash

# Copyright 2020 Antrea Authors.
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

# This script checks commonly misspelled English words. This script is inspired
# by kubernetes/hack/verify-spelling.sh.

set -o errexit
set -o nounset
set -o pipefail

# if Go environment variable is set, use it as it is, otherwise default to "go"
: "${GO:=go}"
TOOL_VERSION="v0.3.4"

GO_VERSION="$(${GO} version | awk '{print $3}')"
function version_lt() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" != "$1"; }

if version_lt "${GO_VERSION}" "go1.16"; then
    # See https://golang.org/doc/go-get-install-deprecation
    echo "Running this script requires Go >= 1.16, please upgrade"
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

TMP_DIR=$(mktemp -d)

# cleanup
exitHandler() (
  echo "Cleaning up temporary directory"
  rm -rf "${TMP_DIR}"
)
trap exitHandler EXIT

GOBIN="${TMP_DIR}" ${GO} install "github.com/client9/misspell/cmd/misspell@${TOOL_VERSION}"
export PATH="${TMP_DIR}:${PATH}"

# Check spelling and ignore skipped files.
RES=0
echo "Spell check start"
ERROR_LOG="${TMP_DIR}/errors.log"
skipping_file="${ROOT}/hack/.spelling_failures"
failing_packages=$(sed "s| | -e |g" "${skipping_file}")
git ls-files | grep -v -e "${failing_packages}"| xargs misspell > "${ERROR_LOG}"
if [[ -s "${ERROR_LOG}" ]]; then
  sed 's/^/error: /' "${ERROR_LOG}"
  echo "Found spelling errors!"
  RES=1
fi
exit "${RES}"
