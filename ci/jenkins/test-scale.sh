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

KIND_CLUSTER=""
DEFAULT_WORKDIR="/var/lib/jenkins"
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/kube.conf
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
TESTCASE=""
TEST_FAILURE=false
DOCKER_REGISTRY=$(head -n1 "${WORKSPACE}/ci/docker-registry")
TESTBED_TYPE="legacy"
IMAGE_PULL_POLICY="Always"
GOLANG_RELEASE_DIR=${WORKDIR}/golang-releases

CONTROL_PLANE_NODE_ROLE="master|control-plane"

CLEAN_STALE_IMAGES="docker system prune --force --all --filter until=4h"
CLEAN_STALE_IMAGES_CONTAINERD="crictl rmi --prune"
PRINT_DOCKER_STATUS="docker system df -v"
PRINT_CONTAINERD_STATUS="crictl ps --state Exited"

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--testcase <e2e|conformance|networkpolicy>]

Run K8s e2e community tests (Conformance & Network Policy) or Antrea e2e tests on a remote (Jenkins) Windows or Linux cluster.

        --kubeconfig             Path of cluster kubeconfig.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase               Windows install OVS, Conformance and Network Policy or Antrea e2e testcases on a Windows or Linux cluster. It can also be flexible ipam or multicast e2e test.
        --registry               The docker registry to use instead of dockerhub.
        --testbed-type           The testbed type to run tests. It can be flexible-ipam, jumper or legacy." 

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
    --kind-cluster-name)
    KIND_CLUSTER="$2"
    shift 2
    ;;
    --kubeconfig)
    KUBECONFIG_PATH="$2"
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
    --testbed-type)
    TESTBED_TYPE="$2"
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

if [[ "$WORKDIR" != "$DEFAULT_WORKDIR" && "$KUBECONFIG_PATH" == "$DEFAULT_KUBECONFIG_PATH" ]]; then
    KUBECONFIG_PATH=${WORKDIR}/.kube/config
fi
NO_PULL=
if [[ "$DOCKER_REGISTRY" != "" ]]; then
    # Image pulling policy of Sonobuoy is 'Always' by default. With dockerhub rate limit, sometimes it is better to use
    # cache when registry is used.
    IMAGE_PULL_POLICY="IfNotPresent"
    # If DOCKER_REGISTRY is non null, we ensure that "make" commands never pull from docker.io.
    NO_PULL=1
fi
export NO_PULL

function export_govc_env_var {
    env_govc="${WORKDIR}/govc.env"
    if [ -f "$env_govc" ]; then
        source "$env_govc"
    else
        export GOVC_URL=$GOVC_URL
    fi
    export GOVC_USERNAME=$GOVC_USERNAME
    export GOVC_PASSWORD=$GOVC_PASSWORD
    export GOVC_INSECURE=1
    export GOVC_DATACENTER=$GOVC_DATACENTER
    export GOVC_DATASTORE=$GOVC_DATASTORE
}

function clean_antrea {
    echo "====== Cleanup Antrea Installation ======"
    clean_ns "antrea-scale-ns"

    # Delete antrea-prometheus first for k8s>=1.22 to avoid Pod stuck in Terminating state.
    kubectl delete -f ${WORKDIR}/antrea-prometheus.yml --ignore-not-found=true || true
    for antrea_yml in ${WORKDIR}/*.yml; do
        kubectl delete -f $antrea_yml --ignore-not-found=true || true
    done
    docker images | grep 'antrea' | awk '{print $3}' | xargs -r docker rmi || true
    docker images | grep '<none>' | awk '{print $3}' | xargs -r docker rmi || true
}

function clean_ns {
    ns=$1
    matching_ns=$(kubectl get ns | awk -v ns="${ns}" '$1 ~ ns {print $1}')
    
    if [ -n "${matching_ns}" ]; then
        echo "${matching_ns}" | while read -r ns_name; do
            kubectl get pod -n "${ns_name}" --no-headers=true | awk '{print $1}' | while read pod_name; do
                kubectl delete pod "${pod_name}" -n "${ns_name}" --force --grace-period 0
            done
            kubectl delete ns "${ns_name}" --ignore-not-found=true || true
        done
    else
        echo "No matching namespaces $ns found."
    fi
}

function prepare_env {
    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKSPACE}/../gocache
    export PATH=${GOROOT}/bin:$PATH

    git show --numstat
    make clean
}

function deliver_antrea_scale {
    echo "====== Cleanup Antrea Installation Before Delivering Antrea ======"
    clean_antrea
    kubectl delete -f ${WORKDIR}/antrea-prometheus.yml || true
    kubectl delete daemonset antrea-agent -n kube-system || true
    kubectl delete -f ${WORKDIR}/antrea.yml || true

    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE="${WORKSPACE}/../gocache"
    export PATH=${GOROOT}/bin:$PATH

    git show --numstat
    make clean
    ${CLEAN_STALE_IMAGES}
    ${PRINT_DOCKER_STATUS}

    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull
    make build-scale-simulator

    # Generate antrea scale yaml
    make manifest-scale
    # Enable verbose log for troubleshooting.
    sed -i "s/--v=0/--v=4/g" build/yamls/antrea-scale.yml

    echo "=== Fill serviceCIDRv6 and serviceCIDR ==="
    # It is unnecessary for cluster with AntreaProxy enabled.
    SVCCIDRS=$(kubectl cluster-info dump | grep service-cluster-ip-range | head -n 1 | cut -d'=' -f2 | cut -d'"' -f1)
    echo "Service CIDRs are $SVCCIDRS"
    regexV6="^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}.*$"
    IFS=',' read -ra CIDRS <<< "$SVCCIDRS"
    for cidr in "${CIDRS[@]}"; do
        if [[ ${cidr} =~ ${regexV6} ]]; then
            sed -i "s|#serviceCIDRv6:|serviceCIDRv6: ${cidr}|g" build/yamls/antrea-scale.yml
        else
            sed -i "s|#serviceCIDR: 10.96.0.0/12|serviceCIDR: ${cidr}|g" build/yamls/antrea-scale.yml
        fi
    done

    echo  "=== Append antrea-prometheus.yml to antrea.yml ==="
    echo "---" >> build/yamls/antrea-scale.yml
    cat build/yamls/antrea-prometheus.yml >> build/yamls/antrea-scale.yml

    control_plane_ip="$(kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 ~ role {print $6}')"
    scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" build/yamls/*.yml jenkins@[${control_plane_ip}]:${WORKDIR}/
    
    cp -f build/yamls/*.yml $WORKDIR

    echo "====== Delivering Antrea Simulators to all Nodes ======"
    docker save -o antrea-ubuntu.tar antrea/antrea-ubuntu:latest
    docker save -o antrea-ubuntu-simulator.tar antrea/antrea-ubuntu-simulator:latest

    kubectl get nodes -o wide --no-headers=true | awk '{print $6}' | while read IP; do
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" antrea-ubuntu.tar jenkins@[${IP}]:${DEFAULT_WORKDIR}/antrea-ubuntu.tar
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" antrea-ubuntu-simulator.tar jenkins@[${IP}]:${DEFAULT_WORKDIR}/antrea-ubuntu-simulator.tar
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" -n jenkins@${IP} "${CLEAN_STALE_IMAGES_CONTAINERD}; ${PRINT_CONTAINERD_STATUS}; ctr -n=k8s.io images import ${DEFAULT_WORKDIR}/antrea-ubuntu.tar" || true
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" -n jenkins@${IP} "ctr -n=k8s.io images import ${DEFAULT_WORKDIR}/antrea-ubuntu-simulator.tar" || true
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
        if [[ "${sshconfig_nodename}" =~ "win" ]]; then
            sed -i "s/capv/administrator/g" "${SSH_CONFIG_DST}.new"
        else
            sed -i "s/capv/jenkins/g" "${SSH_CONFIG_DST}.new"
        fi
        echo "    IdentityFile ${WORKDIR}/.ssh/id_rsa" >> "${SSH_CONFIG_DST}.new"
        cat "${SSH_CONFIG_DST}.new" >> "${SSH_CONFIG_DST}"
    done
}

function prepare_scale_simulator {
    ## Try best to clean up old config.
    kubectl delete -f "${WORKSPACE}/build/yamls/antrea-agent-simulator.yml" || true
    kubectl delete secret kubeconfig || true

    # Create simulators.
    kubectl taint -l 'antrea/instance=simulator' node mocknode=true:NoExecute
    kubectl create secret generic kubeconfig --type=Opaque --namespace=kube-system --from-file=admin.conf=${WORKDIR}/.kube

    kubectl apply -f "${WORKSPACE}/build/yamls/antrea-agent-simulator.yml"
}

function run_scale_test {
    echo "====== Running Antrea Scale Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"
    cp -f "${WORKDIR}/kube.conf" "${WORKDIR}/.kube/config"
    generate_ssh_config

    set +e
    ls ${WORKSPACE}
    make bin
    ${WORKSPACE}/bin/antrea-scale --config ./test/performance/scale.yml
    set -e

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

export KUBECONFIG=${KUBECONFIG_PATH}

source $WORKSPACE/ci/jenkins/utils.sh
check_and_upgrade_golang
clean_tmp

#trap clean_antrea EXIT
#deliver_antrea_scale
prepare_scale_simulator
run_scale_test

if [[ ${TEST_FAILURE} == true ]]; then
    exit 1
fi
