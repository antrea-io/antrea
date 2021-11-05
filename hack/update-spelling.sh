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

set -o errexit
set -o nounset
set -o pipefail

TOOL_VERSION="v0.3.4"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

TMP_DIR=$(mktemp -d)

exitHandler() (
  echo "Cleaning up temporary directory"
  rm -rf "${TMP_DIR}"
)
trap exitHandler EXIT

cd "${TMP_DIR}"
GO111MODULE=on GOBIN="${TMP_DIR}" go install "github.com/client9/misspell/cmd/misspell@${TOOL_VERSION}"
export PATH="${TMP_DIR}:${PATH}"
cd "${ROOT}"

# Check spelling and ignore skipped files.
echo "Spell check start"
ERROR_LOG="${TMP_DIR}/errors.log"
skipping_file="${ROOT}/hack/.spelling_failures"
failing_packages=$(sed "s| | -e |g" "${skipping_file}")
git ls-files | grep -v -e "${failing_packages}"| xargs misspell -w > "${ERROR_LOG}"
if [[ -s "${ERROR_LOG}" ]]; then
  sed 's/^/error: /' "${ERROR_LOG}"
  echo "Fixed spelling errors!"
fi
exit
