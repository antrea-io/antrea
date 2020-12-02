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

RUN_CONFORMANCE=false
RUN_WHOLE_CONFORMANCE=false
RUN_NETWORK_POLICY=false
RUN_E2E_FOCUS=""
KUBECONFIG_OPTION=""
E2E_CONFORMANCE_SKIP="\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]"
MODE="report"
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
KUBE_CONFORMANCE_IMAGE_VERSION="$(head -n1 $THIS_DIR/k8s-conformance-image-version)"

_usage="Usage: $0 [--e2e-conformance] [--e2e-network-policy] [--e2e-focus <TestRegex>] [--e2e-conformance-skip <SkipRegex>]
                  [--kubeconfig <Kubeconfig>] [--kube-conformance-image-version <ConformanceImageVersion>]
                  [--log-mode <SonobuoyResultLogLevel>]
Run the K8s e2e community tests (Conformance & Network Policy) which are relevant to Project Antrea,
using the sonobuoy tool.
        --e2e-conformance                                         Run Conformance tests.
        --e2e-whole-conformance                                   Run whole Conformance tests.
        --e2e-network-policy                                      Run Network Policy tests.
        --e2e-all                                                 Run both Conformance and Network Policy tests.
        --e2e-focus TestRegex                                     Run only tests matching a specific regex, this is useful to run a single tests for example.
        --kubeconfig Kubeconfig                                   Explicit path to Kubeconfig file. You may also set the KUBECONFIG environment variable.
        --kube-conformance-image-version ConformanceImageVersion  Use specific version of the Conformance tests container image. Default is $KUBE_CONFORMANCE_IMAGE_VERSION.
        --log-mode                                                Use the flag to set either 'report', 'detail', or 'dump' level data for sonobouy results.
        --help, -h                                                Print this message and exit

This tool uses sonobuoy (https://github.com/vmware-tanzu/sonobuoy) to run the K8s e2e community
tests which are relevant to Antrea. You can set the SONOBUOY environment variable to the path of the
sonobuoy binary you want to use. Otherwise we will look for sonobuoy in your PATH. If we cannot find
sonobuoy there, we will try to install it."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --kubeconfig)
    KUBECONFIG_OPTION="--kubeconfig $2"
    shift 2
    ;;
    --kube-conformance-image-version)
    KUBE_CONFORMANCE_IMAGE_VERSION="$2"
    shift 2
    ;;
    --e2e-conformance)
    RUN_CONFORMANCE=true
    shift
    ;;
    --e2e-whole-conformance)
    RUN_WHOLE_CONFORMANCE=true
    shift
    ;;
    --e2e-network-policy)
    RUN_NETWORK_POLICY=true
    shift
    ;;
    --e2e-all)
    RUN_CONFORMANCE=true
    RUN_NETWORK_POLICY=true
    shift
    ;;
    --e2e-focus)
    RUN_E2E_FOCUS="$2"
    shift 2
    ;;
    --e2e-conformance-skip)
    E2E_CONFORMANCE_SKIP="$2"
    shift 2
    ;;
    --log-mode)
    MODE="$2"
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

source $THIS_DIR/verify-sonobuoy.sh

if [ -z "$SONOBUOY" ]; then
    SONOBUOY="$(verify_sonobuoy)"
elif ! $SONOBUOY version > /dev/null 2>&1; then
    echoerr "$SONOBUOY does not appear to be a valid sonobuoy binary"
    print_help
    exit 1
fi

echoerr "Using this sonobuoy: $SONOBUOY"

function run_sonobuoy() {
    local focus_regex="$1"
    local skip_regex="$2"
    $SONOBUOY delete --wait $KUBECONFIG_OPTION
    echo "Running tests with sonobuoy. While test is running, check logs with: $SONOBUOY $KUBECONFIG_OPTION logs -f."
    if [[ "$focus_regex" == "" && "$skip_regex" == "" ]]; then
        $SONOBUOY run --wait \
                $KUBECONFIG_OPTION \
                --kube-conformance-image-version $KUBE_CONFORMANCE_IMAGE_VERSION \
                --mode "certified-conformance"
    else
        $SONOBUOY run --wait \
                $KUBECONFIG_OPTION \
                --kube-conformance-image-version $KUBE_CONFORMANCE_IMAGE_VERSION \
                --e2e-focus "$focus_regex" --e2e-skip "$skip_regex"
    fi
    results=$($SONOBUOY retrieve $KUBECONFIG_OPTION)
    $SONOBUOY results $results --mode=$MODE
}

function run_conformance() {
    run_sonobuoy "\[Conformance\]" ${E2E_CONFORMANCE_SKIP}
}

function run_whole_conformance() {
    run_sonobuoy "" ""
}

function run_network_policy() {
    run_sonobuoy "\[Feature:NetworkPolicy\]" ""
}

if $RUN_CONFORMANCE; then
    run_conformance
fi

if $RUN_WHOLE_CONFORMANCE; then
    run_whole_conformance
fi

if $RUN_NETWORK_POLICY; then
    run_network_policy
fi

if [[ $RUN_E2E_FOCUS != "" ]]; then
    run_sonobuoy "$RUN_E2E_FOCUS" ""
fi

echoerr "Deleting sonobuoy resources because tests were successful"
$SONOBUOY delete --wait $KUBECONFIG_OPTION
