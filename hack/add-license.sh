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

# if Go environment variable is set, use it as it is, otherwise default to "go"
: "${GO:=go}"

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

echo "==> Installing addlicense <=="
GOBIN="${TMP_DIR}" ${GO} install "github.com/google/addlicense@latest"
export PATH="${TMP_DIR}:${PATH}"

ADD=false

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --add)
    ADD=true
    shift
    ;;
esac
done

if $ADD; then
    echo "===> Adding License for files <==="
    addlicense -c "Antrea Authors." -y $(date +%Y) `find . -type f -name "*.go"` `find . -type f -name "*.sh"`
else
    echo "===> Checking License for files <==="
    addlicense -c "Antrea Authors." -check `find . -type f -name "*.go"` `find . -type f -name "*.sh"`
fi
