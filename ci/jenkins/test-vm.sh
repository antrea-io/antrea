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

DOCKER_REGISTRY="projects.registry.vmware.com"
DEFAULT_WORKDIR="/var/lib/jenkins"
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/kube.conf
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
TEST_FAILURE=false

# VM configuration
WINDOWS_VM_IP=""
UBUNTU_VM_IP=""
LIN_HOSTNAME="vmbmtest0-1"
WIN_HOSTNAME="vmbmtest0-win-0"

# Cluster configuration
CLUSTER_NAME="kubernetes"
TEST_NAMESPACE="vm-ns"
SERVICE_ACCOUNT="vm-agent"

CONTROL_PLANE_NODE_ROLE="control-plane"

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>] [--workdir <HomePath>]

Run K8s e2e community tests (Conformance & Network Policy) or Antrea e2e tests on a remote (Jenkins) Windows or Linux cluster.

        --kubeconfig             Path of cluster kubeconfig.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
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
    --kubeconfig)
    KUBECONFIG_PATH="$2"
    shift 2
    ;;
    --workdir)
    WORKDIR="$2"
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

if [[ "$WORKDIR" != "$DEFAULT_WORKDIR" && "$KUBECONFIG_PATH" == "$DEFAULT_KUBECONFIG_PATH" ]]; then
    KUBECONFIG_PATH=${WORKDIR}/.kube/config
fi

# To run kubectl cmds
export KUBECONFIG=${KUBECONFIG_PATH}

function export_govc_env_var {
    # This should be coming from jenkins configuration
    export GOVC_URL=$GOVC_URL
    export GOVC_USERNAME=$GOVC_USERNAME
    export GOVC_PASSWORD=$GOVC_PASSWORD
    export GOVC_INSECURE=1
    export GOVC_DATACENTER=$GOVC_DATACENTER
    export GOVC_DATASTORE=$GOVC_DATASTORE
}

function clean_up_one_ns {
    ns=$1
    kubectl get pod -n "${ns}" --no-headers=true | awk '{print $1}' | while read pod_name; do
        kubectl delete pod "${pod_name}" -n "${ns}" --force --grace-period 0
    done
    kubectl delete ns "${ns}" --ignore-not-found=true || true
}

function clean_antrea {
    echo "====== Cleanup Antrea Installation ======"
    clean_up_one_ns $TEST_NAMESPACE
    kubectl delete -f ${WORKDIR}/antrea.yml --ignore-not-found=true
}

function apply_antrea {
    # Ensure that files in the Docker context have the correct permissions, or Docker caching cannot
    # be leveraged successfully
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    # Pull images from Dockerhub first then try Harbor.
    for i in `seq 3`; do
        VERSION="$CLUSTER_NAME" ./hack/build-antrea-linux-all.sh --pull && break
    done
    if [ $? -ne 0 ]; then
        echoerr "Failed to build antrea images with Dockerhub"
        for i in `seq 3`; do
          VERSION="$CLUSTER_NAME" DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull && break
        done
        if [ $? -ne 0 ]; then
            echoerr "Failed to build antrea images with Harbor"
            exit 1
        fi
    fi
    echo "====== Applying Antrea yaml ======"
    ./hack/generate-manifest.sh --export-controller-nodeport 32767 --enable-externalnode > ${WORKDIR}/antrea.yml
    kubectl apply -f ${WORKDIR}/antrea.yml
}

function clean_vm_agent {
    echo "====== Cleanup Antrea-Agent Installation on the VM ======"
    echo "Revert to snapshot VMAgent"
    govc snapshot.revert -k=true -vm=${LIN_HOSTNAME} VMAgent
    govc snapshot.revert -k=true -vm=${WIN_HOSTNAME} VMAgent
    echo "Get IP addresses for VMs"
    UBUNTU_VM_IP=$(govc vm.ip -k=true -wait=1m ${LIN_HOSTNAME})
    for i in `seq 10`; do
        WINDOWS_VM_IP=$(govc vm.ip -k=true -wait=2m ${WIN_HOSTNAME})
        if [[ WINDOWS_VM_IP == "" ]]; then
            echo "Failed to retrieve IP for Windows VM ${WIN_HOSTNAME}, retry ${i}"
            continue
        fi
    done

    kubectl delete sa $SERVICE_ACCOUNT -n $TEST_NAMESPACE --ignore-not-found=true
    clean_up_one_ns $TEST_NAMESPACE
    echo "Deleting stale antrea-agent files from ${LIN_HOSTNAME} and ${WIN_HOSTNAME}"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ubuntu@${UBUNTU_VM_IP} "rm -rf /tmp/antrea-ci"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" Administrator@${WINDOWS_VM_IP} "rm -rf /tmp/antrea-ci"
}

function configure_vm_agent {
    echo "====== Configuring Antrea agent on the VM ======"
    echo "Create ns $TEST_NAMESPACE"
    kubectl create ns $TEST_NAMESPACE
    echo "Create service account $SERVICE_ACCOUNT"
    kubectl create sa $SERVICE_ACCOUNT -n $TEST_NAMESPACE
    cp ./build/yamls/externalnode/vm-agent-rbac.yml ${WORKDIR}/vm-agent-rbac.yml
    echo "Applying vm-agent rbac yaml"
    kubectl apply -f ${WORKDIR}/vm-agent-rbac.yml

    echo "Creating files antrea-agent.kubeconfig and antrea-agent.antrea.kubeconfig"
    # Kubeconfig to access K8S API
    APISERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}")
    TOKEN=$(kubectl -n $TEST_NAMESPACE get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='$SERVICE_ACCOUNT')].data.token}"|base64 --decode)
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.kubeconfig set-cluster kubernetes --server=$APISERVER --insecure-skip-tls-verify=true
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.kubeconfig set-credentials antrea-agent --token=$TOKEN
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.kubeconfig set-context antrea-agent@kubernetes --cluster=kubernetes --user=antrea-agent
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.kubeconfig use-context antrea-agent@kubernetes

    # Kubeconfig to access AntreaController
    ANTREA_API_SERVER_IP=$(kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role {print $6}')
    ANTREA_API_SERVER="https://${ANTREA_API_SERVER_IP}:32767"
    TOKEN=$(kubectl -n $TEST_NAMESPACE get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='$SERVICE_ACCOUNT')].data.token}"|base64 --decode)
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.antrea.kubeconfig set-cluster antrea --server=$ANTREA_API_SERVER --insecure-skip-tls-verify=true
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.antrea.kubeconfig set-credentials antrea-agent --token=$TOKEN
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.antrea.kubeconfig set-context antrea-agent@antrea --cluster=antrea --user=antrea-agent
    kubectl config --kubeconfig=${WORKDIR}/antrea-agent.antrea.kubeconfig use-context antrea-agent@antrea

    echo "Copying kubeconfig files to Linux VM"
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.antrea.kubeconfig ubuntu@${UBUNTU_VM_IP}:/tmp/antrea-ci/antrea-agent.antrea.kubeconfig
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.kubeconfig  ubuntu@${UBUNTU_VM_IP}:/tmp/antrea-ci/antrea-agent.kubeconfig
    echo "Copying kubeconfig files to Windows VM"
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.antrea.kubeconfig Administrator@${WINDOWS_VM_IP}:/tmp/antrea-ci/antrea-agent.antrea.kubeconfig
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.kubeconfig Administrator@${WINDOWS_VM_IP}:/tmp/antrea-ci/antrea-agent.kubeconfig
    echo "Configure antrea-agent as a service on Linux VM"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ubuntu@${UBUNTU_VM_IP} "sudo cp /tmp/antrea-ci/antrea-agent /usr/sbin/"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ubuntu@${UBUNTU_VM_IP} "sudo cp /tmp/antrea-ci/antrea-agent.conf /var/run/antrea/"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ubuntu@${UBUNTU_VM_IP} "sudo cp /tmp/antrea-ci/antrea-agent.*kubeconfig /var/run/antrea/"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ubuntu@${UBUNTU_VM_IP} "sudo systemctl daemon-reload"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ubuntu@${UBUNTU_VM_IP} "sudo systemctl enable antrea-agent"
    echo "Configure antrea-agent as a service on Windows VM"
    # change /tmp/antrea-ci/*kubeconfig to C:\antrea-agent\*kubeconfig
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" Administrator@${WINDOWS_VM_IP} "sed -i 's|/tmp/antrea-ci|C:/antrea-agent|g' /tmp/antrea-ci/antrea-agent.conf"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" Administrator@${WINDOWS_VM_IP} "cp /tmp/antrea-ci/antrea-agent.exe C:/antrea-agent/"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" Administrator@${WINDOWS_VM_IP} "cp /tmp/antrea-ci/antrea-agent.conf C:/antrea-agent/antrea-agent.conf"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" Administrator@${WINDOWS_VM_IP} "cp /tmp/antrea-ci/antrea-agent.*kubeconfig C:/antrea-agent/"
}


function run_e2e_vms {
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    configure_vm_agent
    echo "====== Running Antrea e2e Tests for VM ======"
    mkdir -p `pwd`/antrea-test-logs
    go test -v -timeout=100m antrea.io/antrea/test/e2e -run=TestVMAgent --logs-export-dir `pwd`/antrea-test-logs -provider=remote -windowsVMs=${WIN_HOSTNAME} -linuxVMs=${LIN_HOSTNAME}
    if [[ "$?" != "0" ]]; then
        TEST_FAILURE=true
    fi
    set -e

    tar -zcf antrea-test-logs.tar.gz antrea-test-logs
}

function deliver_antrea_vm {
    export_govc_env_var
    clean_vm_agent
    echo "====== Building Antrea binaries for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKSPACE}/../gocache
    export PATH=${GOROOT}/bin:$PATH

    make docker-bin
    make docker-windows-bin
    echo "====== Delivering Antrea to all the VMs ======"
    cp ./build/yamls/externalnode/conf/antrea-agent.conf ${WORKDIR}/antrea-agent.conf
    echo "Updating antrea-agent.conf"
    sed -i 's|#externalNodeNamespace: default|externalNodeNamespace: vm-ns|g' ${WORKDIR}/antrea-agent.conf
    sed -i 's|kubeconfig: |kubeconfig: /tmp/antrea-ci/|g' ${WORKDIR}/antrea-agent.conf
    echo "Copying binaries and conf to VM: $LIN_HOSTNAME"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ubuntu@${UBUNTU_VM_IP} "mkdir -p /tmp/antrea-ci"
    scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antrea-agent ubuntu@${UBUNTU_VM_IP}:/tmp/antrea-ci/antrea-agent
    scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antctl ubuntu@${UBUNTU_VM_IP}:/tmp/antrea-ci/antctl
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.conf  ubuntu@${UBUNTU_VM_IP}:/tmp/antrea-ci/antrea-agent.conf
    echo "Copying binaries and conf to VM: $WIN_HOSTNAME"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" Administrator@${WINDOWS_VM_IP} "mkdir -p /tmp/antrea-ci"
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antrea-agent.exe Administrator@${WINDOWS_VM_IP}:/tmp/antrea-ci/antrea-agent.exe
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antctl.exe Administrator@${WINDOWS_VM_IP}:/tmp/antrea-ci/antctl.exe
    scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.conf  Administrator@${WINDOWS_VM_IP}:/tmp/antrea-ci/antrea-agent.conf
}

trap clean_antrea EXIT
apply_antrea
deliver_antrea_vm
run_e2e_vms
