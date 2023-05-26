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

# The script validates the Prometheus metrics list within docs/prometheus-integration.md againt a Kind cluster.

set -eo pipefail

# mktemp on macOS does not not support a suffix (file extension in the template)
METRICS_TMP_DOC=$(mktemp /tmp/metricsdoc.XXXXXX)

function exit_handler() {
    echo "Cleaning up..."
    if [ -f $METRICS_TMP_DOC ]; then
        rm -rf $METRICS_TMP_DOC
    fi
}

trap exit_handler INT EXIT

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
MAKE_CMD="$THIS_DIR/../../hack/make-metrics-doc.sh"
METRICS_DOC="$THIS_DIR/../../docs/prometheus-integration.md"

cp -v $METRICS_DOC $METRICS_TMP_DOC
$MAKE_CMD $METRICS_TMP_DOC
result=0
cmp -s $METRICS_DOC $METRICS_TMP_DOC || result=$?
if [ $result -ne 0 ]; then
    echo "Error: Prometheus metrics document should be updated"
    echo "You can update it by building the Antrea Docker image locally (with 'make'), running ./hack/make-metrics-doc.sh and committing the changes"
    exit 1
fi

echo "Prometheus Metrics document verified successfully"
exit 0
