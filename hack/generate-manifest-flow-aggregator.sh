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

_usage="Usage: $0 [--mode (dev|release)] [-fc|--flow-collector <addr>] [-ch|--clickhouse] [--verbose-log] [--help|-h]
Generate a YAML manifest for the Flow Aggregator, using Helm and Kustomize, and print it to stdout.
        --mode (dev|release)            Choose the configuration variant that you need (default is 'dev').
        --flow-collector, -fc <addr>    Specify the flowCollector address.
                                        It should be given in format IP:port:proto. Example: 192.168.1.100:4739:udp.
        --clickhouse, -ch               Enable exporting flow records to default ClickHouse service address.
        --coverage                      Generate a manifest which supports measuring code coverage of the Flow Aggregator binaries.
        --verbose-log                   Generate a manifest with increased log-level (level 4) for the Flow Aggregator.
                                        This option will work only with 'dev' mode.
        --help, -h                      Print this message and exit.

In 'release' mode, environment variables IMG_NAME and IMG_TAG must be set.

In 'dev' mode, environment variable IMG_NAME can be set to use a custom image.

This tool uses Helm 3 (https://helm.sh/) and Kustomize (https://github.com/kubernetes-sigs/kustomize)
to generate the manifest for Flow Aggregator. You can set the HELM and KUSTOMIZE environment
variable to the paths of the helm and kustomize binaries you want us to use. Otherwise we
will download the appropriate version of the helm and kustomize binary and use it (this is
the recommended approach since different versions of helm and kustomize may create different
output YAMLs)."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
FLOW_COLLECTOR=""
CLICKHOUSE=false
COVERAGE=false
VERBOSE_LOG=false

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
    -ch|--clickhouse)
    CLICKHOUSE=true
    shift
    ;;
    --coverage)
    COVERAGE=true
    shift
    ;;
    --verbose-log)
    VERBOSE_LOG=true
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

if [ "$MODE" != "dev" ] && $VERBOSE_LOG; then
    echoerr "--verbose-log works only with 'dev' mode"
    print_help
    exit 1
fi

if $COVERAGE && $VERBOSE_LOG; then
    echoerr "--coverage has enabled verbose log"
    VERBOSE_LOG=false
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

source $THIS_DIR/verify-kustomize.sh

if [ -z "$KUSTOMIZE" ]; then
    KUSTOMIZE="$(verify_kustomize)"
elif ! $KUSTOMIZE version > /dev/null 2>&1; then
    echoerr "$KUSTOMIZE does not appear to be a valid kustomize binary"
    print_help
    exit 1
fi

HELM_VALUES=()

if [[ $FLOW_COLLECTOR != "" ]]; then
    HELM_VALUES+=("flowCollector.enable=true,flowCollector.address=$FLOW_COLLECTOR")
fi

if $CLICKHOUSE; then
    HELM_VALUES+=("clickHouse.enable=true")
fi

if $COVERAGE; then
    HELM_VALUES+=("testing.coverage=true")
fi 

if [ "$MODE" == "dev" ]; then
    if [[ -z "$IMG_NAME" ]]; then
        if $COVERAGE; then
            HELM_VALUES+=("image.repository=antrea/flow-aggregator-coverage")
        fi
    else
        HELM_VALUES+=("image.repository=$IMG_NAME")
    fi

    if $VERBOSE_LOG; then
        HELM_VALUES+=("logVerbosity=4")
    fi
fi

if [ "$MODE" == "release" ]; then
    HELM_VALUES+=("image.repository=$IMG_NAME,image.tag=$IMG_TAG")
fi

delim=""
HELM_VALUES_OPTION=""
for v in "${HELM_VALUES[@]}"; do
    HELM_VALUES_OPTION="$HELM_VALUES_OPTION$delim$v"
    delim=","
done
if [ "$HELM_VALUES_OPTION" != "" ]; then
    HELM_VALUES_OPTION="--set $HELM_VALUES_OPTION"
fi

ANTREA_CHART=$THIS_DIR/../build/charts/flow-aggregator
KUSTOMIZATION_DIR=$THIS_DIR/../build/yamls/flow-aggregator
# intermediate manifest
MANIFEST=$KUSTOMIZATION_DIR/base/manifest.yaml
# Suppress potential Helm warnings about invalid permissions for Kubeconfig file
# by throwing away related warnings.
$HELM template \
      --namespace flow-aggregator \
      $HELM_VALUES_OPTION \
      "$ANTREA_CHART"\
      2> >(grep -v 'This is insecure' >&2)\
      > $MANIFEST

# Add flow-aggregator Namespace resource with Kustomize
cd $KUSTOMIZATION_DIR/base
$KUSTOMIZE build

rm -rf $MANIFEST
