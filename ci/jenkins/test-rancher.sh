#!/usr/bin/env bash

# Copyright 2023 Antrea Authors
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

DEFAULT_WORKDIR=$HOME
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=""
TESTCASE=""
TEST_FAILURE=false
MODE="report"
DOCKER_REGISTRY=$(head -n1 "${WORKSPACE}/ci/docker-registry")
GO_VERSION=$(head -n1 "${WORKSPACE}/build/images/deps/go-version")
IMAGE_PULL_POLICY="Always"
GOLANG_RELEASE_DIR=${WORKDIR}/golang-releases

CLUSTER_NAME=""

CLEAN_STALE_IMAGES="docker system prune --force --all --filter until=48h"

_usage="Usage: $0 [--cluster-name <NameOfTheRancherCluster>] [--workdir <HomePath>]
                  [--testcase <e2e|conformance|networkpolicy>]

Run K8s e2e community tests (Conformance & Network Policy) or Antrea e2e tests on a remote (Jenkins) Rancher cluster.

        --cluster-name           Name of the kubernetes cluster.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase               Conformance and Network Policy or Antrea e2e testcases on a Rancher cluster.
        --registry               The docker registry to use instead of dockerhub."

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
    --cluster-name)
    CLUSTER_NAME="$2"
    shift 2
    ;;
    --workdir)
    WORKDIR="$2"
    shift 2
    ;;
    --testcase)
    TESTCASE="$2"
    shift 2
    ;;
    --registry)
    DOCKER_REGISTRY="$2"
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

if [[ "$DOCKER_REGISTRY" != "" ]]; then
    # Image pulling policy of Sonobuoy is 'Always' by default. With dockerhub rate limit, sometimes it is better to use
    # cache when registry is used.
    IMAGE_PULL_POLICY="IfNotPresent"
fi

RANCHER='sudo /home/ubuntu/rancher-v2.7.0/./rancher'

function rancher_login {
    ${RANCHER} login $RANCHER_URL --token $RANCHER_ACCESS_TOKEN --skip-verify --context $RANCHER_UPSTREAM_CONTEXT
}

function fetch_kubeconfig {
    ${RANCHER} cluster kf $CLUSTER_NAME -o yaml > "$1"
}

function export_govc_env_var {
    export GOVC_URL=$GOVC_URL_FOR_RANCHER
    export GOVC_USERNAME=$GOVC_USERNAME
    export GOVC_PASSWORD=$GOVC_PASSWORD
    export GOVC_INSECURE=1
    export GOVC_DATACENTER=$GOVC_DATACENTER
    export GOVC_DATASTORE=$GOVC_DATASTORE
}

function clean_vm_agent {
    echo "====== Cleanup Antrea-Agent Installation on the VM ======"
    echo "Revert to snapshot defaultState"
    export_govc_env_var
    ${RANCHER} nodes | awk 'NR>1 {print $2}' | while read HOSTNAME; do
        govc snapshot.revert -k=true -vm=${HOSTNAME} defaultState
    done
}

function deliver_antrea {
    echo "====== Cleanup Antrea Installation ======"
    clean_vm_agent

    echo "====== Fetch and Export Kubeconfig ======"
    KUBECONFIG_PATH="$(readlink -f .)/kubeconfig"
    fetch_kubeconfig $KUBECONFIG_PATH
    export KUBECONFIG=$KUBECONFIG_PATH

    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE="${WORKSPACE}/../gocache"
    export PATH=${GOROOT}/bin:$PATH

    git show --numstat
    make clean
    ${CLEAN_STALE_IMAGES}
    check_and_upgrade_golang
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull
    make flow-aggregator-image

    # Enable verbose log for troubleshooting.
    sed -i "s/--v=0/--v=4/g" build/yamls/antrea.yml

    echo  "=== Append antrea-prometheus.yml to antrea.yml ==="
    echo "---" >> build/yamls/antrea.yml
    cat build/yamls/antrea-prometheus.yml >> build/yamls/antrea.yml
    control_plane_ip="$(kubectl get nodes -l node-role.kubernetes.io/control-plane -o wide --no-headers=true | awk '{print $6}')"

    cp -f build/yamls/*.yml $WORKDIR
    scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" build/yamls/*.yml ubuntu@[${control_plane_ip}]:~/

    echo "====== Delivering Antrea to all the Nodes ======"
    docker save -o antrea-ubuntu.tar antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest
    docker save -o flow-aggregator.tar antrea/flow-aggregator:latest
    kubectl get nodes -o wide --no-headers=true | awk '{print $6}' | while read IP; do
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar ubuntu@[${IP}]:~/antrea-ubuntu.tar
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" flow-aggregator.tar ubuntu@[${IP}]:~/flow-aggregator.tar
        ssh -o StrictHostKeyChecking=no -n ubuntu@${IP} "${CLEAN_STALE_IMAGES}; docker load -i ~/antrea-ubuntu.tar; docker load -i ~/flow-aggregator.tar" || true
    done
}

function generate_ssh_config {
    echo "=== Generate ssh-config ==="
    SSH_CONFIG_DST="${WORKDIR}/.ssh/config"
    echo -n "" > "${SSH_CONFIG_DST}"
    kubectl get nodes -o wide --no-headers=true | awk '{print $1}' | while read sshconfig_nodename; do
        echo "Generating ssh-config for Node ${sshconfig_nodename}"
        sshconfig_nodeip="$(kubectl get node "${sshconfig_nodename}" -o jsonpath='{.status.addresses[0].address}')"
        # Add square brackets to ipv6 address
        if [[ ! "${sshconfig_nodeip}" =~ ^[0-9]+(\.[0-9]+){3}$ ]];then
            sshconfig_nodeip="[${sshconfig_nodeip}]"
        fi
        cp ci/jenkins/ssh-config "${SSH_CONFIG_DST}.new"
        sed -i "s/SSHCONFIGNODEIP/${sshconfig_nodeip}/g" "${SSH_CONFIG_DST}.new"
        sed -i "s/SSHCONFIGNODENAME/${sshconfig_nodename}/g" "${SSH_CONFIG_DST}.new"
        sed -i "s/capv/ubuntu/g" "${SSH_CONFIG_DST}.new"
        echo "    IdentityFile ${WORKDIR}/.ssh/id_rsa" >> "${SSH_CONFIG_DST}.new"
        cat "${SSH_CONFIG_DST}.new" >> "${SSH_CONFIG_DST}"
    done
}

function run_e2e {
    echo "====== Running Antrea E2E Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"

    generate_ssh_config

    control_plane_node_name="$(kubectl get nodes -l node-role.kubernetes.io/control-plane -o wide --no-headers=true | awk '{print $1}')"
    kubectl config use-context ${control_plane_node_name}

    echo "=== Move kubeconfig to all Nodes ==="
    kubectl get nodes -o wide --no-headers=true | awk '{print $6}' | while read IP; do
        ssh -o StrictHostKeyChecking=no -n ubuntu@${IP} "if [ ! -d ".kube" ]; then mkdir .kube; fi"
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" $KUBECONFIG_PATH ubuntu@[${IP}]:~/.kube/config
    done

    mkdir -p `pwd`/antrea-test-logs
    # HACK: see https://github.com/antrea-io/antrea/issues/2292
    go mod edit -replace github.com/moby/spdystream=github.com/antoninbas/spdystream@v0.2.1 && go mod tidy
    set +e
    go test -v antrea.io/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs --provider remote -remote.kubeconfig="$KUBECONFIG_PATH" -timeout=100m --prometheus
    if [[ "$?" != "0" ]]; then
        TEST_FAILURE=true
    fi
    set -e

    tar -zcf antrea-test-logs.tar.gz antrea-test-logs
}

function run_conformance {
    echo "====== Running Antrea Conformance Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    kubectl apply -f build/yamls/antrea.yml
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status deployment/coredns -n kube-system
    kubectl rollout status deployment.apps/antrea-controller -n kube-system
    kubectl rollout status daemonset/antrea-agent -n kube-system

    if [[ "$TESTCASE" =~ "conformance" ]]; then
        ${WORKSPACE}/ci/run-k8s-e2e-tests.sh --e2e-conformance --log-mode $MODE --image-pull-policy ${IMAGE_PULL_POLICY} --kubernetes-version "auto" > ${WORKSPACE}/test-result.log
    else
        ${WORKSPACE}/ci/run-k8s-e2e-tests.sh --e2e-network-policy --log-mode $MODE --image-pull-policy ${IMAGE_PULL_POLICY} --kubernetes-version "auto" > ${WORKSPACE}/test-result.log
    fi

    cat ${WORKSPACE}/test-result.log
    if grep -Fxq "Failed tests:" ${WORKSPACE}/test-result.log; then
        echo "Failed cases exist."
        TEST_FAILURE=true
    else
        echo "All tests passed."
    fi
}

function clean_tmp() {
    echo "===== Clean up stale files & folders older than 7 days under /tmp ====="
    CLEAN_LIST=(
        "*codecov*"
        "kustomize-*"
        "*antrea*"
        "go-build*"
    )
    for item in "${CLEAN_LIST[@]}"; do
        find /tmp -name "${item}" -mtime +7 -exec rm -rf {} \; 2>&1 | grep -v "Permission denied" || true
    done
    find ${WORKDIR} -name "support-bundles*" -mtime +7 -exec rm -rf {} \; 2>&1 | grep -v "Permission denied" || true
}

rancher_login

source $WORKSPACE/ci/jenkins/utils.sh
check_and_upgrade_golang
clean_tmp
trap clean_vm_agent EXIT
deliver_antrea
if [[ ${TESTCASE} =~ "e2e" ]]; then
    run_e2e
else
    run_conformance
fi

if [[ ${TEST_FAILURE} == true ]]; then
    exit 1
fi
