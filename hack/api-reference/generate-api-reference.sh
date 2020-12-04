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

# This script is used to generate the reference docs for the Antrea API, which
# is included in the antrea.io website.

set -eo pipefail

OUTPUT=api-reference.html

TMP_DIR=$(mktemp -d)

function exit_handler() {
    rm -rf $TMP_DIR
}

trap exit_handler INT EXIT

git clone --branch antrea https://github.com/antoninbas/gen-crd-api-reference-docs.git $TMP_DIR/refdocs
cd $TMP_DIR/refdocs && go build -o gen && cd -

BIN=$TMP_DIR/refdocs/gen

$BIN -config gen-config.json -api-dir github.com/vmware-tanzu/antrea/pkg/apis -out-file $OUTPUT -template-dir template -skip-missing-api-version

echo "API reference doc generated as $OUTPUT"
