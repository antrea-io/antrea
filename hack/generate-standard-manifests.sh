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
Generate standard YAML manifests for Antrea using Helm and writes them to output directory.
        --mode (dev|release)          Choose the configuration variant that you need (default is 'dev')
        --out <DIR>                   Output directory for generated manifetss
        --help, -h                    Print this message and exit

In 'release' mode, environment variables IMG_NAME and IMG_TAG must be set.

In 'dev' mode, environment variable IMG_NAME can be set to use a custom image.

This tool uses Helm 3 (https://helm.sh/) to generate the \"standard\" manifests for Antrea. These
are the manifests that are checked-in into the Antrea source tree, and that are uploaded as release
assets for each new Antrea release. This script looks for all the Helm values YAML files under
/build/yamls/chart-values/, and generates the corresponding manifest for each one.

You can set the HELM environment variable to the path of the helm binary you wan t us to
use. Otherwise we will download the appropriate version of the helm binary and use it (this is the
recommended approach since different versions of helm may create different output YAMLs)."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
OUTPUT_DIR=""

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --mode)
    MODE="$2"
    shift 2
    ;;
    --out)
    OUTPUT_DIR="$2"
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

if [ "$MODE" != "dev" ] && [ "$MODE" != "release" ]; then
    echoerr "--mode must be one of 'dev' or 'release'"
    print_help
    exit 1
fi

if [ "$MODE" == "release" ] && [ -z "$IMG_NAME" ]; then
    echoerr "In 'release' mode, environment variable IMG_NAME must be set"
    print_help
    exit 1
fi

if [ "$MODE" == "release" ] && [ -z "$IMG_TAG" ]; then
    echoerr "In 'release' mode, environment variable IMG_TAG must be set"
    print_help
    exit 1
fi

if [ "$OUTPUT_DIR" == "" ]; then
    echoerr "--out is required to provide output directory for generated manifests"
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

EXTRA_VALUES=""
if [ "$MODE" == "release" ]; then
    EXTRA_VALUES="--set image.repository=$IMG_NAME,image.tag=$IMG_TAG"
fi

ANTREA_CHART="$THIS_DIR/../build/charts/antrea"
VALUES_DIR="$THIS_DIR/../build/yamls/chart-values"
VALUES_FILES=$(cd $VALUES_DIR && find * -type f -name "*.yml" )
# Suppress potential Helm warnings about invalid permissions for Kubeconfig file
# by throwing away related warnings.
for values in $VALUES_FILES; do
    $HELM template \
          --namespace kube-system \
          -f "$VALUES_DIR/$values" \
          $EXTRA_VALUES \
          "$ANTREA_CHART" \
          > "$OUTPUT_DIR/$values" \
          2> >(grep -v 'This is insecure' >&2)
done
