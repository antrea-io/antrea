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
RUN_E2E_SKIP=""
KUBECONFIG_OPTION=""
DEFAULT_E2E_CONFORMANCE_FOCUS="\[Conformance\]"
DEFAULT_E2E_CONFORMANCE_SKIP="\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]|\[sig-instrumentation\]|Ingress API|IngressClass API"
DEFAULT_E2E_NETWORKPOLICY_FOCUS="\[Feature:NetworkPolicy\]"
DEFAULT_E2E_NETWORKPOLICY_SKIP=""
MODE="report"
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
KUBE_CONFORMANCE_IMAGE_VERSION="$(head -n1 $THIS_DIR/k8s-conformance-image-version)"
IMAGE_PULL_POLICY="Always"
CONFORMANCE_IMAGE_CONFIG_PATH="${THIS_DIR}/conformance-image-config.yaml"
SONOBUOY_IMAGE="projects.registry.vmware.com/sonobuoy/sonobuoy:v0.19.0"

_usage="Usage: $0 [--e2e-conformance] [--e2e-network-policy] [--e2e-focus <TestRegex>] [--e2e-skip <SkipRegex>]
                  [--kubeconfig <Kubeconfig>] [--kube-conformance-image-version <ConformanceImageVersion>]
                  [--log-mode <SonobuoyResultLogLevel>]
Run the K8s e2e community tests (Conformance & Network Policy) which are relevant to Project Antrea,
using the sonobuoy tool.
        --e2e-conformance                                         Run Conformance tests.
        --e2e-whole-conformance                                   Run whole Conformance tests.
        --e2e-network-policy                                      Run Network Policy tests.
        --e2e-all                                                 Run both Conformance and Network Policy tests.
        --e2e-focus TestRegex                                     Run only tests matching a specific regex, this is useful to run a single tests for example.
        --e2e-skip TestRegex                                      Skip some tests matching a specific regex.
        --kubeconfig Kubeconfig                                   Explicit path to Kubeconfig file. You may also set the KUBECONFIG environment variable.
        --kube-conformance-image-version ConformanceImageVersion  Use specific version of the Conformance tests container image. Default is $KUBE_CONFORMANCE_IMAGE_VERSION.
        --log-mode                                                Use the flag to set either 'report', 'detail', or 'dump' level data for sonobouy results.
        --image-pull-policy                                       The ImagePullPolicy Sonobuoy should use for the aggregators and workers. (default Always)
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
    --e2e-skip)
    RUN_E2E_SKIP="$2"
    shift 2
    ;;
    --log-mode)
    MODE="$2"
    shift 2
    ;;
    --image-pull-policy)
    IMAGE_PULL_POLICY="$2"
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
    set -x
    if [[ "$focus_regex" == "" && "$skip_regex" == "" ]]; then
        $SONOBUOY run --wait \
                $KUBECONFIG_OPTION \
                --kube-conformance-image-version $KUBE_CONFORMANCE_IMAGE_VERSION \
                --mode "certified-conformance" --image-pull-policy ${IMAGE_PULL_POLICY} \
                --sonobuoy-image ${SONOBUOY_IMAGE} --e2e-repo-config ${CONFORMANCE_IMAGE_CONFIG_PATH}
    else
        $SONOBUOY run --wait \
                $KUBECONFIG_OPTION \
                --kube-conformance-image-version $KUBE_CONFORMANCE_IMAGE_VERSION \
                --e2e-focus "$focus_regex" --e2e-skip "$skip_regex" --image-pull-policy ${IMAGE_PULL_POLICY} \
                --sonobuoy-image ${SONOBUOY_IMAGE} --e2e-repo-config ${CONFORMANCE_IMAGE_CONFIG_PATH}
    fi
    set +x
    results=$($SONOBUOY retrieve $KUBECONFIG_OPTION)
    $SONOBUOY results $results --mode=$MODE
}

function run_conformance() {
    if [[ "$RUN_E2E_FOCUS" != "" ]]; then
        echo "It is not allowed to specify focus when running conformance tests"
        exit 1
    fi
    if [[ "$RUN_E2E_SKIP" == "" ]]; then
        RUN_E2E_SKIP="${DEFAULT_E2E_CONFORMANCE_SKIP}"
    fi
    run_sonobuoy "${DEFAULT_E2E_CONFORMANCE_FOCUS}" "${RUN_E2E_SKIP}"
}

function run_whole_conformance() {
    run_sonobuoy "" ""
}

function run_network_policy() {
    if [[ "$RUN_E2E_FOCUS" != "" ]]; then
        echo "It is not allowed to specify focus when running network policy tests"
        exit 1
    fi
    if [[ "$RUN_E2E_SKIP" == "" ]]; then
        RUN_E2E_SKIP="${DEFAULT_E2E_NETWORKPOLICY_SKIP}"
    fi
    run_sonobuoy "${DEFAULT_E2E_NETWORKPOLICY_FOCUS}" "${RUN_E2E_SKIP}"
}

if [[ "$RUN_E2E_FOCUS" != "" ]]; then
    run_sonobuoy "$RUN_E2E_FOCUS" "$RUN_E2E_SKIP"
fi

if $RUN_CONFORMANCE; then
    run_conformance
fi

if $RUN_WHOLE_CONFORMANCE; then
    run_whole_conformance
fi

if $RUN_NETWORK_POLICY; then
    run_network_policy
fi

echoerr "Deleting sonobuoy resources because tests were successful"
$SONOBUOY delete --wait $KUBECONFIG_OPTION
