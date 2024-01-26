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
ANTREA_AGENT_KUBECONFIG="antrea-agent.kubeconfig"
ANTREA_AGENT_ANTREA_KUBECONFIG="antrea-agent.antrea.kubeconfig"
SNAPSHOT="InstallVMAgent"
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/kube.conf
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
TEST_FAILURE=false
GOLANG_RELEASE_DIR=${WORKDIR}/golang-releases

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

# VM configuration
declare -A LINUX_HOSTS_TO_IP
declare -A WINDOWS_HOSTS_TO_IP
declare -a LIN_HOSTNAMES=("vmbmtest0-1" "vmbmtest0-redhat-0")
declare -a WIN_HOSTNAMES=("vmbmtest0-win-0")
declare -A LINUX_HOSTS_TO_USERNAME=(["vmbmtest0-1"]="ubuntu" ["vmbmtest0-redhat-0"]="root")
declare -A WINDOWS_HOSTS_TO_USERNAME=(["vmbmtest0-win-0"]="Administrator")

# To run kubectl cmds
export KUBECONFIG=${KUBECONFIG_PATH}

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
    kubectl delete ns "${ns}" --ignore-not-found=true || true
}

function clean_antrea {
    echo "====== Cleanup Antrea Installation ======"
    clean_up_one_ns $TEST_NAMESPACE
    kubectl delete -f ${WORKDIR}/antrea.yml --ignore-not-found=true
    # The cleanup and stats are best-effort.
    set +e
    docker system prune --force --all --filter until=1h > /dev/null
    docker system df -v
    set -e
}

function apply_antrea {
    # Ensure that files in the Docker context have the correct permissions, or Docker caching cannot
    # be leveraged successfully
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    # Pull images from Dockerhub first then try Harbor.
    for i in `seq 3`; do
        ./hack/build-antrea-linux-all.sh --pull && break
    done
    if [ $? -ne 0 ]; then
        echoerr "Failed to build antrea images with Dockerhub"
        for i in `seq 3`; do
            DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull && break
        done
        if [ $? -ne 0 ]; then
            echoerr "Failed to build antrea images with Harbor"
            exit 1
        fi
    fi
    TEMP_ANTREA_TAR="antrea-image.tar"
    docker save antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest -o $TEMP_ANTREA_TAR
    ctr -n k8s.io image import $TEMP_ANTREA_TAR
    rm $TEMP_ANTREA_TAR
    echo "====== Applying Antrea yaml ======"
    ./hack/generate-manifest.sh --feature-gates ExternalNode=true,SupportBundleCollection=true --extra-helm-values "controller.apiNodePort=32767" > ${WORKDIR}/antrea.yml
    kubectl apply -f ${WORKDIR}/antrea.yml
}

function clean_vm_agent {
    host_names=( "$@" )
    echo "Host names ${host_names[@]}"
    kubectl delete sa $SERVICE_ACCOUNT -n $TEST_NAMESPACE --ignore-not-found=true
    clean_up_one_ns $TEST_NAMESPACE
    for host_name in "${host_names[@]}"; do
        echo "====== Cleanup Antrea-Agent Installation on the $host_name VM ======"
        echo "Revert to snapshot $SNAPSHOT"
        govc snapshot.revert -k=true -vm=$host_name $SNAPSHOT
    done
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
    cp ./build/yamls/externalnode/support-bundle-collection-rbac.yml ${WORKDIR}/support-bundle-collection-rbac.yml
    echo "Applying support-bundle-collection rbac yaml"
    kubectl apply -f ${WORKDIR}/support-bundle-collection-rbac.yml -n $TEST_NAMESPACE
    cp ./hack/externalnode/sftp-deployment.yml ${WORKDIR}/sftp-deployment.yml
    cp ./hack/externalnode/install-vm.sh ${WORKDIR}/install-vm.sh
    cp ./hack/externalnode/install-vm.ps1 ${WORKDIR}/install-vm.ps1
    create_kubeconfig_files
    copy_antrea_agent_files_on_linux
    install_on_linux
    copy_antrea_agent_files_on_windows
    install_on_windows
}

function fetch_vm_ip {
    echo "Fetching the ip address for LINUX VMs"
    for host_name in "${LIN_HOSTNAMES[@]}"; do
        LINUX_HOSTS_TO_IP["$host_name"]=$(govc vm.ip -k=true -wait=1m ${host_name})
    done
    echo "Fetching the ip address for WINDOWS VMs"
    for host_name in "${WIN_HOSTNAMES[@]}"; do
        for i in `seq 10`; do
            WINDOWS_HOSTS_TO_IP["$host_name"]=$(govc vm.ip -k=true -wait=2m ${host_name})
            if [[ WINDOWS_HOSTS_TO_IP["$host_name"] == "" ]]; then
                echo "Failed to retrieve IP for Windows VM ${host_name}, retry ${i}"
                continue
            fi
            break
        done
    done
}

function create_kubeconfig_files {
    echo "Creating files ${ANTREA_AGENT_KUBECONFIG} and ${ANTREA_AGENT_ANTREA_KUBECONFIG}"
    # Kubeconfig to access K8S API

    SECRET_NAME="${SERVICE_ACCOUNT}-service-account-token"
    APISERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}")
    TOKEN=$(kubectl -n $TEST_NAMESPACE get secrets ${SECRET_NAME} -o json | jq -r .data.token | base64 --decode)
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_KUBECONFIG} set-cluster kubernetes --server=$APISERVER --insecure-skip-tls-verify=true
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_KUBECONFIG} set-credentials antrea-agent --token=$TOKEN
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_KUBECONFIG} set-context antrea-agent@kubernetes --cluster=kubernetes --user=antrea-agent
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_KUBECONFIG} use-context antrea-agent@kubernetes

    # Kubeconfig to access AntreaController
    ANTREA_API_SERVER_IP=$(kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 == role {print $6}')
    ANTREA_API_SERVER="https://${ANTREA_API_SERVER_IP}:32767"
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_ANTREA_KUBECONFIG} set-cluster antrea --server=$ANTREA_API_SERVER --insecure-skip-tls-verify=true
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_ANTREA_KUBECONFIG} set-credentials antrea-agent --token=$TOKEN
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_ANTREA_KUBECONFIG} set-context antrea-agent@antrea --cluster=antrea --user=antrea-agent
    kubectl config --kubeconfig=${WORKDIR}/${ANTREA_AGENT_ANTREA_KUBECONFIG} use-context antrea-agent@antrea
}

function copy_antrea_agent_files_on_linux {
    echo "====== Delivering Antrea files to all the LINUX VMs ======"
    for host_name in "${LIN_HOSTNAMES[@]}"; do
        echo "Copying binaries and conf to VM: $host_name"
        USERNAME=${LINUX_HOSTS_TO_USERNAME[${host_name}]}
        IP_ADDRESS=${LINUX_HOSTS_TO_IP[${host_name}]}
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ${USERNAME}@${IP_ADDRESS} "mkdir -p /tmp/antrea-ci"
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antrea-agent ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/antrea-agent
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antctl ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/antctl
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.conf  ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/antrea-agent.conf
        echo "Copying kubeconfig files to Linux VM: $host_name"
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/${ANTREA_AGENT_ANTREA_KUBECONFIG} ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/${ANTREA_AGENT_ANTREA_KUBECONFIG}
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/${ANTREA_AGENT_KUBECONFIG}  ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/${ANTREA_AGENT_KUBECONFIG}
        echo "Copying install script to Linux VM: $host_name"
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/install-vm.sh  ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/install-vm.sh
    done
}

function copy_antrea_agent_files_on_windows {
    echo "====== Delivering Antrea files to all the WINDOWS VMs ======"
    for host_name in "${WIN_HOSTNAMES[@]}"; do
        echo "Copying binaries and conf to VM: $host_name"
        USERNAME=${WINDOWS_HOSTS_TO_USERNAME[${host_name}]}
        IP_ADDRESS=${WINDOWS_HOSTS_TO_IP[${host_name}]}
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${USERNAME}@${IP_ADDRESS} "mkdir -p /tmp/antrea-ci"
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antrea-agent.exe ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/antrea-agent.exe
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ./bin/antctl.exe ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/antctl.exe
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/antrea-agent.conf  ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/antrea-agent.conf
        echo "Copying kubeconfig files to Windows VM: $host_name"
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/${ANTREA_AGENT_ANTREA_KUBECONFIG} ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/${ANTREA_AGENT_ANTREA_KUBECONFIG}
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/${ANTREA_AGENT_KUBECONFIG} ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/${ANTREA_AGENT_KUBECONFIG}
        echo "Copying install script to Windows VM: $host_name"
        scp -q -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${WORKDIR}/install-vm.ps1  ${USERNAME}@${IP_ADDRESS}:/tmp/antrea-ci/install-vm.ps1
    done
}

function install_on_linux {
   for host_name in "${LIN_HOSTNAMES[@]}"; do
      echo "Installing on Linux VM $host_name"
      USERNAME=${LINUX_HOSTS_TO_USERNAME[${host_name}]}
      IP_ADDRESS=${LINUX_HOSTS_TO_IP[${host_name}]}
      ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ${USERNAME}@${IP_ADDRESS} "sudo chmod +x /tmp/antrea-ci/install-vm.sh"
      ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n ${USERNAME}@${IP_ADDRESS} "cd /tmp/antrea-ci && sudo ./install-vm.sh --ns vm-ns --bin ./antrea-agent --config ./antrea-agent.conf --kubeconfig ./antrea-agent.kubeconfig  --antrea-kubeconfig ./antrea-agent.antrea.kubeconfig"
   done
}

function install_on_windows {
   for host_name in "${WIN_HOSTNAMES[@]}"; do
      echo "Installing on Windows VM $host_name"
      USERNAME=${WINDOWS_HOSTS_TO_USERNAME[${host_name}]}
      IP_ADDRESS=${WINDOWS_HOSTS_TO_IP[${host_name}]}
      ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" ${USERNAME}@${IP_ADDRESS} "cd /tmp/antrea-ci && Powershell -ExecutionPolicy Bypass -NoProfile -File install-vm.ps1 -Namespace vm-ns -BinaryPath antrea-agent.exe -ConfigPath antrea-agent.conf -KubeConfigPath antrea-agent.kubeconfig -AntreaKubeConfigPath antrea-agent.antrea.kubeconfig"
   done
}

function run_e2e_vms {
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    configure_vm_agent
    echo "====== Running Antrea e2e Tests for VM ======"
    set +e
    mkdir -p `pwd`/antrea-test-logs
    go test -v -timeout=100m antrea.io/antrea/test/e2e -run=TestVMAgent --logs-export-dir `pwd`/antrea-test-logs -provider=remote -windowsVMs="${WIN_HOSTNAMES[*]}" -linuxVMs="${LIN_HOSTNAMES[*]}"
    if [[ "$?" != "0" ]]; then
        TEST_FAILURE=true
    fi
    set -e

    tar -zcf antrea-test-logs.tar.gz antrea-test-logs
}

function build_antrea_binary {
    export_govc_env_var
    clean_vm_agent ${LIN_HOSTNAMES[@]}
    clean_vm_agent ${WIN_HOSTNAMES[@]}
    echo "====== Building Antrea binaries for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKSPACE}/../gocache
    export PATH=${GOROOT}/bin:$PATH

    make docker-bin
    make docker-windows-bin

    cp ./build/yamls/externalnode/conf/antrea-agent.conf ${WORKDIR}/antrea-agent.conf
}

trap clean_antrea EXIT
source $WORKSPACE/ci/jenkins/utils.sh
check_and_upgrade_golang
fetch_vm_ip
apply_antrea
build_antrea_binary
run_e2e_vms

if [[ ${TEST_FAILURE} == true ]]; then
    exit 1
fi
