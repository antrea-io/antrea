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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--mode (dev|release)] [-fc|--flow-collector] [--keep] [--help|-h]
Generate a YAML manifest for flow aggregator, using Kustomize, and print it to stdout.
        --mode (dev|release)  Choose the configuration variant that you need (default is 'dev')
        --flow-collector      Flow collector is the externalFlowCollectorAddr configMap parameter
                              It should be given in format IP:port:proto. Example: 192.168.1.100:4739:udp
        --keep                Debug flag which will preserve the generated kustomization.yml
        --help, -h            Print this message and exit

In 'release' mode, environment variables IMG_NAME and IMG_TAG must be set.

This tool uses kustomize (https://github.com/kubernetes-sigs/kustomize) to generate manifests for
running Antrea on Windows Nodes. You can set the KUSTOMIZE environment variable to the path of the
kustomize binary you want us to use. Otherwise we will look for kustomize in your PATH and your
GOPATH. If we cannot find kustomize there, we will try to install it."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
KEEP=false
FLOW_COLLECTOR=""
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --mode)
    MODE="$2"
    shift 2
    ;;
    -fc|--flow-collector)
    FLOW_COLLECTOR="$2"
    shift 2
    ;;
    --keep)
    KEEP=true
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

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/verify-kustomize.sh

if [ -z "$KUSTOMIZE" ]; then
    KUSTOMIZE="$(verify_kustomize)"
elif ! $KUSTOMIZE version > /dev/null 2>&1; then
    echoerr "$KUSTOMIZE does not appear to be a valid kustomize binary"
    print_help
    exit 1
fi

KUSTOMIZATION_DIR=$THIS_DIR/../build/yamls/flow-aggregator

TMP_DIR=$(mktemp -d $KUSTOMIZATION_DIR/overlays.XXXXXXXX)

pushd $TMP_DIR > /dev/null

BASE=../../base

# do all ConfigMap edits
mkdir configMap && cd configMap
# user is not expected to make changes directly to flow-aggregator.conf,
# but instead to the generated YAML manifest, so our regexs need not be too robust.
cp $KUSTOMIZATION_DIR/base/conf/flow-aggregator.conf flow-aggregator.conf
if [[ $FLOW_COLLECTOR != "" ]]; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*externalFlowCollectorAddr[[:space:]]*:[[:space:]]\"\"+[[:space:]]*$/externalFlowCollectorAddr:  \"$FLOW_COLLECTOR\"/" flow-aggregator.conf
fi

# unfortunately 'kustomize edit add configmap' does not support specifying 'merge' as the behavior,
# which is why we use a template kustomization file.
sed -e "s/<FLOW_AGG_CONF_FILE>/flow-aggregator.conf/" ../../patches/kustomization.configMap.tpl.yml > kustomization.yml
$KUSTOMIZE edit add base $BASE
BASE=../configMap
cd ..

mkdir $MODE && cd $MODE
touch kustomization.yml
$KUSTOMIZE edit add base $BASE
# ../../patches/$MODE may be empty so we use find and not simply cp
find ../../patches/$MODE -name \*.yml -exec cp {} . \;

if [ "$MODE" == "dev" ]; then
    $KUSTOMIZE edit set image flow-aggregator=projects.registry.vmware.com/antrea/flow-aggregator:latest
    $KUSTOMIZE edit add patch --path imagePullPolicy.yml
fi

if [ "$MODE" == "release" ]; then
    $KUSTOMIZE edit set image flow-aggregator=$IMG_NAME:$IMG_TAG
fi

$KUSTOMIZE build

popd > /dev/null

if $KEEP; then
    echoerr "Kustomization file is at $TMP_DIR/$MODE/kustomization.yml"
else
    rm -rf $TMP_DIR
fi
