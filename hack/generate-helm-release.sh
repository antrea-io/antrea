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

_usage="Usage: $0 [--mode (dev|release)] --out <DIR>
Package the Antrea chart and the Flow Aggregator chart into chart archives.
Environment variable VERSION must be set.
        --out <DIR>                   Output directory for chart archives
        --help, -h                    Print this message and exit

You can set the HELM environment variable to the path of the helm binary you want us to
use. Otherwise we will download the appropriate version of the helm binary and use it."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
OUT=""

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --mode)
    MODE="$2"
    shift 2
    ;;
    --out)
    OUT="$2"
    shift 2
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

if [ -z "$VERSION" ]; then
    echoerr "Environment variable VERSION must be set"
    print_help
    exit 1
fi

if [ "$OUT" == "" ]; then
    echoerr "--out is required to provide output path"
    print_help
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/verify-helm.sh

if [ -z "$HELM" ]; then
    HELM="$(verify_helm)"
elif ! $HELM version > /dev/null 2>&1; then
    echoerr "$HELM does not appear to be a valid helm binary"
    print_help
    exit 1
fi

ANTREA_CHART="$THIS_DIR/../build/charts/antrea"
# create a backup file before making changes.
# note that the backup file will not be included in the release: .bak files are
# ignored as per the .helmignore file.
cp "$ANTREA_CHART/Chart.yaml" "$ANTREA_CHART/Chart.yaml.bak"
yq -i '.annotations."artifacthub.io/prerelease" = strenv(PRERELEASE)' "$ANTREA_CHART/Chart.yaml"
$HELM package --app-version $VERSION --version $VERSION $ANTREA_CHART
mv "antrea-$VERSION.tgz" "$OUT/antrea-chart.tgz"
mv "$ANTREA_CHART/Chart.yaml.bak" "$ANTREA_CHART/Chart.yaml"

FLOW_AGGREGATOR_CHART="$THIS_DIR/../build/charts/flow-aggregator"
cp "$FLOW_AGGREGATOR_CHART/Chart.yaml" "$FLOW_AGGREGATOR_CHART/Chart.yaml.bak"
yq -i '.annotations."artifacthub.io/prerelease" = strenv(PRERELEASE)' "$FLOW_AGGREGATOR_CHART/Chart.yaml"
$HELM package --app-version $VERSION --version $VERSION $FLOW_AGGREGATOR_CHART
mv "flow-aggregator-$VERSION.tgz" "$OUT/flow-aggregator-chart.tgz"
mv "$FLOW_AGGREGATOR_CHART/Chart.yaml.bak" "$FLOW_AGGREGATOR_CHART/Chart.yaml"
