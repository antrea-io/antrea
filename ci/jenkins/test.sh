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

KIND_CLUSTER=""
DEFAULT_WORKDIR="/var/lib/jenkins"
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/kube.conf
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
TESTCASE=""
TEST_FAILURE=false
MODE="report"
DOCKER_REGISTRY=$(head -n1 "${WORKSPACE}/ci/docker-registry")
TESTBED_TYPE="legacy"
GO_VERSION=$(head -n1 "${WORKSPACE}/build/images/deps/go-version")
IMAGE_PULL_POLICY="Always"
PROXY_ALL=false
DEFAULT_IP_MODE="ipv4"
IP_MODE=""
K8S_VERSION="1.28.2-00"
WINDOWS_YAML_SUFFIX="windows"
WIN_IMAGE_NODE=""
echo "" > WIN_DHCP
GOLANG_RELEASE_DIR=${WORKDIR}/golang-releases

WINDOWS_CONFORMANCE_FOCUS="\[sig-network\].+\[Conformance\]|\[sig-windows\]"
WINDOWS_CONFORMANCE_SKIP="\[LinuxOnly\]|\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]|\[Privileged\]"
WINDOWS_NETWORKPOLICY_FOCUS="\[Feature:NetworkPolicy\]"
WINDOWS_NETWORKPOLICY_SKIP="SCTP"
WINDOWS_NETWORKPOLICY_CONTAINERD_SKIP="\[sig-storage\]|SCTP"
CONFORMANCE_SKIP="\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]"
NETWORKPOLICY_SKIP="NetworkPolicyLegacy|should allow egress access to server in CIDR block|should enforce except clause while egress access to server in CIDR block"

CONTROL_PLANE_NODE_ROLE="master|control-plane"

CLEAN_STALE_IMAGES="docker system prune --force --all --filter until=4h"
CLEAN_STALE_IMAGES_CONTAINERD="crictl rmi --prune"
PRINT_DOCKER_STATUS="docker system df -v"
PRINT_CONTAINERD_STATUS="crictl ps --state Exited"

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--testcase <windows-install-ovs|windows-containerd-conformance|windows-conformance|windows-containerd-networkpolicy|windows-networkpolicy|windows-containerd-e2e|windows-e2e|e2e|conformance|networkpolicy|multicast-e2e>]

Run K8s e2e community tests (Conformance & Network Policy) or Antrea e2e tests on a remote (Jenkins) Windows or Linux cluster.

        --kubeconfig             Path of cluster kubeconfig.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase               Windows install OVS, Conformance and Network Policy or Antrea e2e testcases on a Windows or Linux cluster. It can also be flexible ipam or multicast e2e test.
        --registry               The docker registry to use instead of dockerhub.
        --proxyall               Enable proxyAll to test AntreaProxy.
        --testbed-type           The testbed type to run tests. It can be flexible-ipam, jumper or legacy.
        --ip-mode                IP mode for flexible-ipam e2e test. Default is $DEFAULT_IP_MODE. It can also be ipv6 or ds.
        --win-image-node         Name of the windows image node in containerd cluster. Images are built by docker on this node.
        --kind-cluster-name      Name of the kind Cluster." 

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
    --proxyall)
    PROXY_ALL=true
    shift
    ;;
    --ip-mode)
    IP_MODE="$2"
    shift 2
    ;;
    --win-image-node)
    WIN_IMAGE_NODE="$2"
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

if [[ "${IP_MODE}" == "" ]]; then
    IP_MODE=${DEFAULT_IP_MODE}
fi
if [[ "${IP_MODE}" != "${DEFAULT_IP_MODE}" && "${IP_MODE}" != "ipv6" && "${IP_MODE}" != "dual" ]]; then
    echoerr "--ip-mode must be ipv4, ipv6 or dual"
    exit 1
fi
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

E2ETEST_PATH=${WORKDIR}/kubernetes/_output/dockerized/bin/linux/amd64/e2e.test

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
    clean_ns "monitoring"
    clean_ns "antrea-ipam-test"
    clean_ns "antrea-test"
    echo "====== Cleanup Conformance Namespaces ======"
    clean_ns "net"
    clean_ns "service"
    clean_ns "x-"
    clean_ns "y-"
    clean_ns "z-"

    # Delete antrea-prometheus first for k8s>=1.22 to avoid Pod stuck in Terminating state.
    kubectl delete -f ${WORKDIR}/antrea-prometheus.yml --ignore-not-found=true || true
    for antrea_yml in ${WORKDIR}/*.yml; do
        kubectl delete -f $antrea_yml --ignore-not-found=true || true
    done
    docker images --format "{{.Repository}}:{{.Tag}}" | grep 'antrea'| xargs -r docker rmi || true
    docker images | grep '<none>' | awk '{print $3}' | xargs -r docker rmi || true
    check_and_cleanup_docker_build_cache
}

function clean_for_windows_install_cni {
    # https://github.com/antrea-io/antrea/issues/1577
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role && $1 ~ /win/ {print $6}' | while read IP; do
        CLEAN_LIST=("/cygdrive/c/opt/cni/bin/antrea.exe" "/cygdrive/c/opt/cni/bin/host-local.exe" "/cygdrive/c/k/antrea/etc/antrea-agent.conf" "/cygdrive/c/etc/cni/net.d/10-antrea.conflist" "/cygdrive/c/k/antrea/bin/antrea-agent.exe")
        for file in "${CLEAN_LIST[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -f ${file}"
        done
    done
}

function collect_windows_network_info_and_logs {
    echo "=== Collecting information after failure ==="
    DEBUG_LOG_PATH="debug_logs"
    mkdir -p "${DEBUG_LOG_PATH}"
    # Collecting logs is best-effort, do not exit immediately on error.
    set +e
    kubectl get pod -n kube-system -l component=antrea-agent --no-headers=true | awk '{print $1}' | while read AGENTNAME; do
        IP=$(kubectl get pod ${AGENTNAME} -n kube-system -o json | jq -r '.status.hostIP')
        mkdir "${DEBUG_LOG_PATH}/${AGENTNAME}"

        echo "=== Collecting '${AGENTNAME}' agent network info after failure ==="
        AGENT_NETWORK_INFO_PATH="${DEBUG_LOG_PATH}/${AGENTNAME}/network_info"
        mkdir "${AGENT_NETWORK_INFO_PATH}"
        if [[ "${AGENTNAME}" =~ "windows" ]]; then
            ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ovs-ofctl dump-flows br-int" > "${AGENT_NETWORK_INFO_PATH}/flows"
            ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ovs-vsctl show" > "${AGENT_NETWORK_INFO_PATH}/db"
            ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ipconfig" > "${AGENT_NETWORK_INFO_PATH}/addrs"
        else
            kubectl exec "${AGENTNAME}" -c antrea-agent -n kube-system -- ovs-ofctl dump-flows br-int > "${AGENT_NETWORK_INFO_PATH}/flows"
            kubectl exec "${AGENTNAME}" -c antrea-agent -n kube-system -- ovs-vsctl show > "${AGENT_NETWORK_INFO_PATH}/db"
            kubectl exec "${AGENTNAME}" -c antrea-agent -n kube-system -- ip a > "${AGENT_NETWORK_INFO_PATH}/addrs"
        fi

        echo "=== Collecting '${AGENTNAME}' antrea agent log after failure ==="
        ANTREA_AGENT_LOG_PATH="${DEBUG_LOG_PATH}/${AGENTNAME}/antrea_agent_log"
        mkdir "${ANTREA_AGENT_LOG_PATH}"
        kubectl logs "${AGENTNAME}" -n kube-system -c antrea-agent > "${ANTREA_AGENT_LOG_PATH}/antrea-agent.log"
        if [[ "${AGENTNAME}" =~ "windows" ]]; then
            echo "Windows agent doesn't have antrea-ovs container"
        else
            kubectl logs "${AGENTNAME}" -n kube-system -c antrea-ovs > "${ANTREA_AGENT_LOG_PATH}/antrea-ovs.log"
        fi
    done

    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role && $1 ~ /win/ {print $1}' | while read NODENAME; do
        IP=$(kubectl get node ${NODENAME} -o json | jq -r '.status.addresses[] | select(.type | test("InternalIP")).address')
        mkdir "${DEBUG_LOG_PATH}/${NODENAME}"

        echo "=== Collecting '${NODENAME}' Node network info after failure ==="
        NODE_NETWORK_INFO_PATH="${DEBUG_LOG_PATH}/${NODENAME}/network_info"
        mkdir "${NODE_NETWORK_INFO_PATH}"
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "powershell.exe get-NetAdapter" > "${NODE_NETWORK_INFO_PATH}/adapters"
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ipconfig.exe" > "${NODE_NETWORK_INFO_PATH}/ipconfig"
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "powershell.exe Get-HNSNetwork" > "${NODE_NETWORK_INFO_PATH}/hns_network"
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "powershell.exe Get-HNSEndpoint" > "${NODE_NETWORK_INFO_PATH}/hns_endpoint"

        echo "=== Collecting '${NODENAME}' kubelet and docker logs after failure ==="
        KUBELET_LOG_PATH="${DEBUG_LOG_PATH}/${NODENAME}/kubelet"
        mkdir "${KUBELET_LOG_PATH}"
        scp -q -o StrictHostKeyChecking=no -T administrator@${IP}:/cygdrive/c/var/log/kubelet/* "${KUBELET_LOG_PATH}"

        DOCKER_LOG_PATH="${DEBUG_LOG_PATH}/${NODENAME}/docker"
        mkdir "${DOCKER_LOG_PATH}"
        scp -q -o StrictHostKeyChecking=no -T administrator@${IP}:'/cygdrive/c/"Program Files"/Docker/dockerd.log*' "${DOCKER_LOG_PATH}"
    done
    set -e
    tar zcf debug_logs.tar.gz "${DEBUG_LOG_PATH}"
}

function check_dhcp_status {
    echo "===== Check Interface DHCP Status ====="
    WINIP=$(kubectl get nodes -o wide --no-headers=true | awk '$1 ~ /win-0/ {print $6}')
    WIN_BRINT_DHCP=$(ssh -o StrictHostKeyChecking=no -n administrator@${WINIP} 'powershell.exe "(Get-NetIPInterface -InterfaceAlias br-int -AddressFamily IPv4).Dhcp"')
    WIN_DHCP=$(<WIN_DHCP)
    if [[ ${WIN_DHCP} == ${WIN_BRINT_DHCP} ]]; then
        echo "Newly created uplink DHCP status is consistent with the original adapter."
    else
        echo "Newly created uplink DHCP status is different from the original adapter. Original DHCP: $WIN_DHCP, br-int DHCP: $WIN_BRINT_DHCP"
        exit 1
    fi
}

function wait_for_antrea_windows_pods_ready {
    kubectl apply -f "${WORKDIR}/antrea.yml"
    if [[ "${PROXY_ALL}" == false && ${TESTCASE} =~ "windows-e2e" ]]; then
        kubectl apply -f "${WORKDIR}/kube-proxy-${WINDOWS_YAML_SUFFIX}.yml"
    fi
    kubectl apply -f "${WORKDIR}/antrea-${WINDOWS_YAML_SUFFIX}.yml"
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status deployment/coredns -n kube-system
    kubectl rollout status deployment.apps/antrea-controller -n kube-system
    kubectl rollout status daemonset/antrea-agent -n kube-system
    kubectl rollout status daemonset.apps/antrea-agent-windows -n kube-system
    if [[ "${PROXY_ALL}" == false && ${TESTCASE} =~ "windows-e2e" ]]; then
        kubectl rollout status daemonset/kube-proxy-windows -n kube-system
    fi
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role && $1 ~ /win/ {print $6}' | while read IP; do
        for i in `seq 5`; do
            sleep 5
            timeout 5s ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell Get-NetAdapter -Name br-int -ErrorAction SilentlyContinue" && break
        done
        sleep 10
    done
    check_dhcp_status
}

function wait_for_antrea_windows_processes_ready {
    kubectl apply -f "${WORKDIR}/antrea.yml"
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status deployment/coredns -n kube-system
    kubectl rollout status deployment.apps/antrea-controller -n kube-system
    kubectl rollout status daemonset/antrea-agent -n kube-system
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role && $1 ~ /win/ {print $6}' | while read IP; do
        echo "===== Run script to startup Antrea agent ====="
        ANTREA_VERSION=$(ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "/cygdrive/c/k/antrea/bin/antrea-agent.exe --version" | awk '{print $3}')
        ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "chmod +x /cygdrive/c/k/antrea/Start-AntreaAgent.ps1 && powershell 'c:\k\antrea\Start-AntreaAgent.ps1 -AntreaVersion ${ANTREA_VERSION}'"
        for i in `seq 5`; do
            sleep 5
            timeout 5s ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell Get-NetAdapter -Name br-int -ErrorAction SilentlyContinue" && break
        done
        sleep 10
    done
    check_dhcp_status
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

function revert_snapshot_windows {
    WIN_NAME=$1
    echo "==== Reverting Windows VM ${WIN_NAME} ====="
    if [[ $WIN_NAME == *"jumper"* ]]; then
        govc snapshot.revert -vm ${WIN_NAME} win-initial
    else
        govc snapshot.revert -vm ${WIN_NAME} pristine-win-initial
    fi
    # If Windows VM fails to power on correctly in time, retry several times.
    winVMIPs=""
    for i in `seq 10`; do
        winVMIPs=$(govc vm.ip -wait=2m -a ${WIN_NAME})
        if [[ $winVMIPs != "" ]]; then
            echo "Windows VM ${WIN_NAME} powered on"
            break
        fi
        echo "Windows VM ${WIN_NAME} failed to power on"
        govc vm.power -on ${WIN_NAME} || true
    done
    if [[ $winVMIPs == "" ]]; then
        echo "Windows VM ${WIN_NAME} didn't power on after 10 tries, exiting"
        exit 1
    fi
    IP=${winVMIPs#*,}
    # Windows VM is reverted to an old snapshot so computer date needs updating.
    for i in `seq 24`; do
        sleep 5
        ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "W32tm /resync /force" | grep successfully && break
    done
    # Avoid potential resync delay error
    sleep 5
}

function deliver_antrea_linux {
    set -e

    echo "==== Start building and delivering Linux Docker images ===="
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull
    if [[ "$TESTCASE" == "windows-networkpolicy-process" ]]; then
        make windows-bin
    fi

    echo "====== Delivering Antrea to all Nodes ======"
    export_govc_env_var

    # Enable verbose log for troubleshooting.
    sed -i "s/--v=0/--v=4/g" build/yamls/antrea-windows.yml

    if [[ "${PROXY_ALL}" == false && ${TESTCASE} =~ "windows-e2e" ]]; then
        sed -i "s|.*proxyAll: true|      proxyAll: false|g" build/yamls/antrea.yml build/yamls/antrea-windows.yml
    else
        echo "====== Updating yaml files to enable proxyAll ======"
        KUBERNETES_SVC_EP_IP=$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[0].ip}')
        KUBERNETES_SVC_EP_PORT=$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].ports[0].port}')
        KUBERNETES_SVC_EP_ADDR="${KUBERNETES_SVC_EP_IP}:${KUBERNETES_SVC_EP_PORT}"
        sed -i "s|.*kubeAPIServerOverride: \"\"|    kubeAPIServerOverride: \"${KUBERNETES_SVC_EP_ADDR}\"|g" build/yamls/antrea.yml build/yamls/antrea-windows.yml
    fi

    cp -f build/yamls/*.yml $WORKDIR
    docker save -o antrea-ubuntu.tar antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest

    echo "===== Pull necessary images on Control-Plane node ====="
    harbor_images=("agnhost:2.13" "nginx:1.15-alpine")
    antrea_images=("e2eteam/agnhost:2.13" "docker.io/library/nginx:1.15-alpine")
    common_images=("registry.k8s.io/e2e-test-images/agnhost:2.29")
    for i in "${!harbor_images[@]}"; do
        docker pull -q "${DOCKER_REGISTRY}/antrea/${harbor_images[i]}"
        docker tag "${DOCKER_REGISTRY}/antrea/${harbor_images[i]}" "${antrea_images[i]}"
    done
    echo "===== Deliver Antrea to Linux worker nodes and pull necessary images on worker nodes ====="
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role && $1 !~ /win/ {print $6}' | while read IP; do
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar jenkins@${IP}:${WORKDIR}/antrea-ubuntu.tar
        ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES}; ${PRINT_DOCKER_STATUS}; docker load -i ${WORKDIR}/antrea-ubuntu.tar" || true

        for i in "${!harbor_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker pull -q ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} && docker tag ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} ${antrea_images[i]}" || true
        done
        # Pull necessary images in advance to avoid transient error
        for image in "${common_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker pull -q ${image}" || true
        done
    done
    echo "==== Finish building and delivering Linux Docker images ===="
}

function deliver_antrea_windows {
    echo "===== Deliver Antrea Windows to Windows worker nodes and pull necessary images on Windows worker nodes ====="
    rm -f antrea-windows.tar.gz
    sed -i 's/if (!(Test-Path $AntreaAgentConfigPath))/if ($true)/' hack/windows/Helper.psm1
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role && $1 ~ /win/ {print $1}' | while read WORKER_NAME; do
        revert_snapshot_windows ${WORKER_NAME}

        # Use a script to run antrea agent in windows Network Policy cases
        if [ "$TESTCASE" == "windows-networkpolicy-process" ]; then
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell stop-service kubelet"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell stop-service docker"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell rm C:\ProgramData\docker\docker.pid" || true
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell start-service docker"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell start-service kubelet"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell start-service ovsdb-server"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell start-service ovs-vswitchd"
            echo "===== Use script to startup antrea agent ====="
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -rf /cygdrive/c/k/antrea && mkdir -p /cygdrive/c/k/antrea/bin && mkdir -p /cygdrive/c/k/antrea/etc && rm -rf /cygdrive/c/opt/cni/bin && mkdir -p /cygdrive/c/opt/cni/bin && mkdir -p /cygdrive/c/etc/cni/net.d"
            scp -o StrictHostKeyChecking=no -T $KUBECONFIG Administrator@${IP}:/cygdrive/c/k/config
            scp -o StrictHostKeyChecking=no -T bin/antrea-agent.exe Administrator@${IP}:/cygdrive/c/k/antrea/bin/
            scp -o StrictHostKeyChecking=no -T bin/antctl.exe Administrator@${IP}:/cygdrive/c/k/antrea/bin/antctl.exe
            scp -o StrictHostKeyChecking=no -T bin/antrea-cni.exe Administrator@${IP}:/cygdrive/c/opt/cni/bin/antrea.exe
            scp -o StrictHostKeyChecking=no -T hack/windows/Start-AntreaAgent.ps1 Administrator@${IP}:/cygdrive/c/k/antrea/
            scp -o StrictHostKeyChecking=no -T hack/windows/Stop-AntreaAgent.ps1 Administrator@${IP}:/cygdrive/c/k/antrea/
            scp -o StrictHostKeyChecking=no -T hack/windows/Helper.psm1 Administrator@${IP}:/cygdrive/c/k/antrea/
            scp -o StrictHostKeyChecking=no -T build/yamls/windows/base/conf/antrea-cni.conflist Administrator@${IP}:/cygdrive/c/etc/cni/net.d/10-antrea.conflist
            scp -o StrictHostKeyChecking=no -T build/yamls/windows/base/conf/antrea-agent.conf Administrator@${IP}:/cygdrive/c/k/antrea/etc
        else
            if ! (test -f antrea-windows.tar.gz); then
                # Compress antrea repo and copy it to a Windows node
                mkdir -p jenkins
                tar --exclude='./jenkins' -czf jenkins/antrea_repo.tar.gz -C "$(pwd)" .
                for i in `seq 2`; do
                    timeout 2m scp -o StrictHostKeyChecking=no -T jenkins/antrea_repo.tar.gz Administrator@${IP}: && break
                done
                echo "=== Build Windows on Windows Node==="
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/golang:${GO_VERSION}-nanoserver && docker tag ${DOCKER_REGISTRY}/antrea/golang:${GO_VERSION}-nanoserver golang:${GO_VERSION}-nanoserver"
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -rf antrea && mkdir antrea && cd antrea && tar -xzf ../antrea_repo.tar.gz > /dev/null && NO_PULL=${NO_PULL}; DOCKER_NETWORK=host make build-windows && docker save -o antrea-windows.tar antrea/antrea-windows:latest && gzip -f antrea-windows.tar" || true
                for i in `seq 2`; do
                    timeout 2m scp -o StrictHostKeyChecking=no -T Administrator@${IP}:antrea/antrea-windows.tar.gz . && break
                done
            else
                for i in `seq 2`; do
                    timeout 2m scp -o StrictHostKeyChecking=no -T antrea-windows.tar.gz Administrator@${IP}: && break
                done
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker load -i antrea-windows.tar.gz"
            fi
        fi
        # Some tests need us.gcr.io/k8s-artifacts-prod/e2e-test-images/agnhost:2.13 image but it is not for windows/amd64 10.0.17763
        # Use e2eteam/agnhost:2.13 instead
        harbor_images=("sigwindowstools-kube-proxy:v1.18.0" "agnhost:2.13" "agnhost:2.13" "agnhost:2.13" "agnhost:2.29" "agnhost:2.29" "e2eteam-jessie-dnsutils:1.0" "e2eteam-jessie-dnsutils:1.0" "e2eteam-pause:3.2" "e2eteam-pause:3.2" "e2eteam-pause:3.2")
        antrea_images=("sigwindowstools/kube-proxy:v1.18.0" "e2eteam/agnhost:2.13" "us.gcr.io/k8s-artifacts-prod/e2e-test-images/agnhost:2.13" "k8sprow.azurecr.io/kubernetes-e2e-test-images/agnhost:2.13" "k8s.gcr.io/e2e-test-images/agnhost:2.29" "registry.k8s.io/e2e-test-images/agnhost:2.29" "e2eteam/jessie-dnsutils:1.0" "gcr.io/kubernetes-e2e-test-images/jessie-dnsutils:1.0" "e2eteam/pause:3.2" "k8s.gcr.io/pause:3.2" "registry.k8s.io/pause:3.2")
        common_images=("mcr.microsoft.com/windows/servercore/iis:latest")
        # Pull necessary images in advance to avoid transient error
        for i in "${!harbor_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull -q ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} && docker tag ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} ${antrea_images[i]}" || true
        done
        for image in "${common_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull -q ${image}" || true
        done
    done
    rm -f antrea-windows.tar.gz
    echo "==== Finish building and delivering Windows Docker images ===="
}

function build_and_deliver_antrea_windows_and_linux_docker_images {
    echo "====== Cleanup Antrea Installation Before Delivering Antrea Windows and Antrea Linux Docker Images ====="
    clean_antrea
    kubectl delete -f ${WORKDIR}/antrea-windows.yml --ignore-not-found=true || true
    kubectl delete -f ${WORKDIR}/kube-proxy-windows.yml --ignore-not-found=true || true
    kubectl delete daemonset antrea-agent -n kube-system --ignore-not-found=true || true
    kubectl delete -f ${WORKDIR}/antrea.yml --ignore-not-found=true || true

    prepare_env
    ${CLEAN_STALE_IMAGES}
    ${PRINT_DOCKER_STATUS}
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
  
    if [[ "$TESTCASE" == "windows-networkpolicy-process" ]]; then
        make windows-bin
    fi

    export_govc_env_var

    # Enable verbose log for troubleshooting.
    sed -i "s/--v=0/--v=4/g" build/yamls/antrea-windows.yml

    if [[ "${PROXY_ALL}" == true ]]; then
        echo "====== Updating yaml files to enable proxyAll ======"
        KUBERNETES_SVC_EP_IP=$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[0].ip}')
        KUBERNETES_SVC_EP_PORT=$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].ports[0].port}')
        KUBERNETES_SVC_EP_ADDR="${KUBERNETES_SVC_EP_IP}:${KUBERNETES_SVC_EP_PORT}"
        sed -i "s|.*kubeAPIServerOverride: \"\"|    kubeAPIServerOverride: \"${KUBERNETES_SVC_EP_ADDR}\"|g" build/yamls/antrea.yml build/yamls/antrea-windows.yml
        sed -i "s|.*proxyAll: false|      proxyAll: true|g" build/yamls/antrea.yml build/yamls/antrea-windows.yml
    fi

    cp -f build/yamls/*.yml $WORKDIR
    echo "====== Delivering Antrea to all Nodes ======"
    set +e
    deliver_antrea_windows &> deliver_antrea_windows.log &
    deliver_antrea_windows_pid=$!
    deliver_antrea_linux
    linux_result=$?
    wait $deliver_antrea_windows_pid
    windows_result=$?
    cat deliver_antrea_windows.log
    if [ $windows_result -ne 0 ] || [ $linux_result -ne 0 ]; then
        exit 1
    fi
    set -e
}

function  build_and_deliver_antrea_windows_and_linux_containerd_images {
    echo "====== Cleanup Antrea Installation Before Delivering Antrea Windows and Antrea Linux containerd Images ====="
    clean_antrea
    kubectl delete -f ${WORKDIR}/antrea-windows-containerd-with-ovs.yml --ignore-not-found=true || true
    kubectl delete -f ${WORKDIR}/kube-proxy-windows-containerd.yml --ignore-not-found=true || true
    kubectl delete daemonset antrea-agent -n kube-system --ignore-not-found=true || true
    kubectl delete -f ${WORKDIR}/antrea.yml --ignore-not-found=true || true

    prepare_env
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    # Clean docker image to save disk space.
    ${CLEAN_STALE_IMAGES}
    ${PRINT_DOCKER_STATUS}
    export_govc_env_var
    # Enable verbose log for troubleshooting.
    sed -i "s/--v=0/--v=4/g" build/yamls/antrea.yml build/yamls/antrea-windows-containerd-with-ovs.yml

    echo "====== Updating yaml files to enable proxyAll ======"
    KUBE_API_SERVER=$(kubectl --kubeconfig=$KubeConfigFile config view -o jsonpath='{.clusters[0].cluster.server}')
    sed -i "s|.*kubeAPIServerOverride: \"\"|    kubeAPIServerOverride: \"${KUBE_API_SERVER}\"|g" build/yamls/antrea.yml build/yamls/antrea-windows-containerd-with-ovs.yml

    cp -f build/yamls/*.yml $WORKDIR
    set +e
    deliver_antrea_windows_containerd &> deliver_antrea_windows_containerd.log &
    deliver_antrea_windows_containerd=$!
    deliver_antrea_linux_containerd
    linux_result=$?
    wait $deliver_antrea_linux_containerd
    windows_result=$?
    cat deliver_antrea_windows_containerd.log
    if [ $windows_result -ne 0 ] || [ $linux_result -ne 0 ]; then
        exit 1
    fi
    set -e
}

function deliver_antrea_linux_containerd {
    set -e

    echo "==== Start building and delivering Linux containerd images ===="
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull
    docker save -o antrea-ubuntu.tar antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest
    echo "===== Pull necessary images on Control-Plane node ====="
    harbor_images=("agnhost:2.13" "nginx:1.15-alpine")
    antrea_images=("e2eteam/agnhost:2.13" "docker.io/library/nginx:1.15-alpine")
    common_images=("registry.k8s.io/e2e-test-images/agnhost:2.29")
    k8s_images=("registry.k8s.io/e2e-test-images/agnhost:2.45" "registry.k8s.io/e2e-test-images/jessie-dnsutils:1.5" "registry.k8s.io/e2e-test-images/nginx:1.14-2")
    e2e_images=("k8sprow.azurecr.io/kubernetes-e2e-test-images/agnhost:2.45" "k8sprow.azurecr.io/kubernetes-e2e-test-images/jessie-dnsutils:1.5" "k8sprow.azurecr.io/kubernetes-e2e-test-images/nginx:1.14-2")

    echo "===== Deliver Antrea YAML to Controller nodes ====="
    IP=$(kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 ~ role {print $6}')
    HOST_IPS=$(ip addr show | grep -oP 'inet \K[\d.]+')
    matched=false
    for host_ip in $HOST_IPS; do
        if [[ $host_ip == $IP ]]; then
            matched=true
            break
        fi
    done
    if [[ $matched == false ]]; then
        # Copy the YAML file only if the jumper node is not the control-plane node.
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" ${WORKDIR}/antrea.yml jenkins@${IP}:${WORKDIR}/antrea.yml
    fi

    echo "===== Deliver Antrea to all Linux nodes and pull necessary images on these nodes ====="
    kubectl get nodes --selector=kubernetes.io/os=linux --no-headers=true -o custom-columns=IP:.status.addresses[0].address | while read -r IP; do
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar jenkins@${IP}:${WORKDIR}/antrea-ubuntu.tar
        ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES_CONTAINERD}; ${PRINT_CONTAINERD_STATUS}; ctr -n=k8s.io images import ${WORKDIR}/antrea-ubuntu.tar" || true

        for i in "${!harbor_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "ctr -n=k8s.io images pull ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} && ctr -n=k8s.io images tag ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} ${antrea_images[i]}" || true
        done
        # Pull necessary images in advance to avoid transient error
        for image in "${common_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "ctr -n=k8s.io images pull ${image}" || true
        done
        # Pull necessary images for Kubernetes conformance test
        for i in "${!k8s_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "ctr -n=k8s.io images pull ${k8s_images[i]} && ctr -n=k8s.io images tag ${k8s_images[i]} ${e2e_images[i]}" || true
        done
    done
    echo "==== Finish building and delivering Linux containerd images ===="
}

function deliver_antrea_windows_containerd {
    echo "===== Build Antrea Windows on Windows Jumper Node ====="
    echo "==== Reverting Windows VM ${WIN_IMAGE_NODE} ====="
    revert_snapshot_windows ${WIN_IMAGE_NODE}
    rm -f antrea-windows.tar.gz
    # Compress antrea repo and copy it to a Windows node
    mkdir -p jenkins
    tar --exclude='./jenkins' -czf jenkins/antrea_repo.tar.gz -C "$(pwd)" .
    for i in `seq 2`; do
        timeout 2m scp -o StrictHostKeyChecking=no -T jenkins/antrea_repo.tar.gz Administrator@${IP}: && break
    done
    ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/golang:${GO_VERSION}-nanoserver && docker tag ${DOCKER_REGISTRY}/antrea/golang:${GO_VERSION}-nanoserver golang:${GO_VERSION}-nanoserver"
    ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -rf antrea && mkdir antrea && cd antrea && tar -xzf ../antrea_repo.tar.gz > /dev/null && NO_PULL=${NO_PULL}; DOCKER_NETWORK=host make build-windows && docker save -o antrea-windows.tar antrea/antrea-windows:latest && gzip -f antrea-windows.tar" || true
    for i in `seq 2`; do
        timeout 2m scp -o StrictHostKeyChecking=no -T Administrator@${IP}:antrea/antrea-windows.tar.gz . && break
    done

    echo "===== Deliver Antrea Windows to Windows worker nodes and pull necessary images on Windows worker nodes ====="
    sed -i 's/if (!(Test-Path $AntreaAgentConfigPath))/if ($true)/' hack/windows/Helper.psm1
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role && $1 ~ /win/ {print $1}' | while read WORKER_NAME; do
        revert_snapshot_windows ${WORKER_NAME}
        # Some tests need us.gcr.io/k8s-artifacts-prod/e2e-test-images/agnhost:2.13 image but it is not for windows/amd64 10.0.17763
        # Use e2eteam/agnhost:2.13 instead
        harbor_images=("sigwindowstools-kube-proxy:v1.18.0" "agnhost:2.13" "agnhost:2.13" "agnhost:2.29" "e2eteam-jessie-dnsutils:1.0" "e2eteam-pause:3.2")
        antrea_images=("sigwindowstools/kube-proxy:v1.18.0" "e2eteam/agnhost:2.13" "us.gcr.io/k8s-artifacts-prod/e2e-test-images/agnhost:2.13" "registry.k8s.io/e2e-test-images/agnhost:2.29" "e2eteam/jessie-dnsutils:1.0" "e2eteam/pause:3.2")
        k8s_images=("registry.k8s.io/e2e-test-images/agnhost:2.45" "registry.k8s.io/e2e-test-images/jessie-dnsutils:1.5" "registry.k8s.io/e2e-test-images/nginx:1.14-2" "registry.k8s.io/pause:3.8")
        e2e_images=("k8sprow.azurecr.io/kubernetes-e2e-test-images/agnhost:2.45" "k8sprow.azurecr.io/kubernetes-e2e-test-images/jessie-dnsutils:1.5" "k8sprow.azurecr.io/kubernetes-e2e-test-images/nginx:1.14-2" "k8sprow.azurecr.io/kubernetes-e2e-test-images/pause:3.8")
        # Pull necessary images in advance to avoid transient error
        for i in "${!harbor_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "ctr -n k8s.io images pull ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} && ctr -n k8s.io images tag ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} ${antrea_images[i]}" || true
        done
        for i in "${!k8s_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "ctr -n k8s.io images pull ${k8s_images[i]} && ctr -n k8s.io images tag ${k8s_images[i]} ${e2e_images[i]}" || true
        done
        if ! (test -f antrea-windows.tar.gz); then
            echo "Windows VM ${WIN_IMAGE_NODE} didn't build antrea-windows.tar.gz, exiting"
            exit 1
        else
            for i in `seq 2`; do
                timeout 2m scp -o StrictHostKeyChecking=no -T antrea-windows.tar.gz Administrator@${IP}: && break
            done
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "gzip -d antrea-windows.tar.gz && ctr -n k8s.io images import antrea-windows.tar"
        fi
    done
    # Add Windows interface DHCP check using CI script to obtain the original interface status.
    WINIP=$(kubectl get nodes -o wide --no-headers=true | awk '$1 ~ /win-0/ {print $6}')
    WIN_DHCP=$(ssh -o StrictHostKeyChecking=no -n administrator@${WINIP} 'powershell.exe "(Get-NetIPInterface -InterfaceAlias \"Ethernet0 2\" -AddressFamily IPv4).Dhcp"')
    echo "Original adapter DHCP status: $WIN_DHCP"
    echo $WIN_DHCP > WIN_DHCP
    rm -f antrea-windows.tar
    echo "==== Finish building and delivering Windows containerd images ===="
}

function deliver_antrea {
    echo "====== Cleanup Antrea Installation Before Delivering Antrea ======"
    clean_antrea
    kubectl delete -f ${WORKDIR}/antrea-prometheus.yml || true
    kubectl delete daemonset antrea-agent -n kube-system || true
    kubectl delete -f ${WORKDIR}/antrea.yml || true
    if [[ $TESTBED_TYPE == "flexible-ipam" ]]; then
        redeploy_k8s_if_ip_mode_changes
    fi

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
    if [[ ! "${TESTCASE}" =~ "e2e" && "${DOCKER_REGISTRY}" != "" ]]; then
        docker pull "${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3"
        docker tag "${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3" "sonobuoy/systemd-logs:v0.3"
    fi
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull
    make flow-aggregator-image

    # Enable verbose log for troubleshooting.
    sed -i "s/--v=0/--v=4/g" build/yamls/antrea.yml

    echo "=== Fill serviceCIDRv6 and serviceCIDR ==="
    # It is unnecessary for cluster with AntreaProxy enabled.
    SVCCIDRS=$(kubectl cluster-info dump | grep service-cluster-ip-range | head -n 1 | cut -d'=' -f2 | cut -d'"' -f1)
    echo "Service CIDRs are $SVCCIDRS"
    regexV6="^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}.*$"
    IFS=',' read -ra CIDRS <<< "$SVCCIDRS"
    for cidr in "${CIDRS[@]}"; do
        if [[ ${cidr} =~ ${regexV6} ]]; then
            sed -i "s|#serviceCIDRv6:|serviceCIDRv6: ${cidr}|g" build/yamls/antrea.yml
        else
            sed -i "s|#serviceCIDR: 10.96.0.0/12|serviceCIDR: ${cidr}|g" build/yamls/antrea.yml
        fi
    done

    echo  "=== Append antrea-prometheus.yml to antrea.yml ==="
    echo "---" >> build/yamls/antrea.yml
    cat build/yamls/antrea-prometheus.yml >> build/yamls/antrea.yml

    if [[ $TESTBED_TYPE == "flexible-ipam" ]]; then
        control_plane_ip="$(kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 ~ role {print $6}')"
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" build/yamls/*.yml jenkins@[${control_plane_ip}]:~
    elif [[ $TESTBED_TYPE == "jumper" ]]; then
        control_plane_ip="$(kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 ~ role {print $6}')"
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" build/yamls/*.yml jenkins@[${control_plane_ip}]:${WORKDIR}/
    else
        cp -f build/yamls/*.yml $WORKDIR
    fi
    cp -f build/yamls/*.yml $WORKDIR

    echo "====== Delivering Antrea to all Nodes ======"
    docker save -o antrea-ubuntu.tar antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest
    docker save -o flow-aggregator.tar antrea/flow-aggregator:latest

    if [[ $TESTBED_TYPE == "flexible-ipam" ]]; then
        kubectl get nodes -o wide --no-headers=true | awk '{print $6}' | while read IP; do
            scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" antrea-ubuntu.tar jenkins@[${IP}]:${DEFAULT_WORKDIR}/antrea-ubuntu.tar
            scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" flow-aggregator.tar jenkins@[${IP}]:${DEFAULT_WORKDIR}/flow-aggregator.tar
            ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n jenkins@${IP} "${CLEAN_STALE_IMAGES_CONTAINERD}; ${PRINT_CONTAINERD_STATUS}; ctr -n=k8s.io images import ${DEFAULT_WORKDIR}/antrea-ubuntu.tar; ctr -n=k8s.io images import ${DEFAULT_WORKDIR}/flow-aggregator.tar" || true
        done
    elif [[ $TESTBED_TYPE == "kind" ]]; then
            kind load docker-image antrea/antrea-agent-ubuntu:latest --name ${KIND_CLUSTER}
            kind load docker-image antrea/antrea-controller-ubuntu:latest --name ${KIND_CLUSTER}
            kind load docker-image antrea/flow-aggregator:latest --name ${KIND_CLUSTER} 
            kubectl config use-context kind-${KIND_CLUSTER}
            docker cp ./build/yamls/antrea.yml ${KIND_CLUSTER}-control-plane:/root/antrea.yml 
    elif [[ $TESTBED_TYPE == "jumper" ]]; then
        kubectl get nodes -o wide --no-headers=true | awk '{print $6}' | while read IP; do
            scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" antrea-ubuntu.tar jenkins@[${IP}]:${DEFAULT_WORKDIR}/antrea-ubuntu.tar
            scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" flow-aggregator.tar jenkins@[${IP}]:${DEFAULT_WORKDIR}/flow-aggregator.tar
            ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/.ssh/id_rsa" -n jenkins@${IP} "${CLEAN_STALE_IMAGES_CONTAINERD}; ${PRINT_CONTAINERD_STATUS}; ctr -n=k8s.io images import ${DEFAULT_WORKDIR}/antrea-ubuntu.tar; ctr -n=k8s.io images import ${DEFAULT_WORKDIR}/flow-aggregator.tar" || true
        done
    else
        kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 !~ role {print $6}' | while read IP; do
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar jenkins@[${IP}]:${WORKDIR}/antrea-ubuntu.tar
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" flow-aggregator.tar jenkins@[${IP}]:${WORKDIR}/flow-aggregator.tar
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES}; ${PRINT_DOCKER_STATUS}; docker load -i ${WORKDIR}/antrea-ubuntu.tar; docker load -i ${WORKDIR}/flow-aggregator.tar" || true
            if [[ ! "${TESTCASE}" =~ "e2e" && "${DOCKER_REGISTRY}" != "" ]]; then
                ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3 ; docker tag ${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3 sonobuoy/systemd-logs:v0.3"
            fi
        done
    fi
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

function run_e2e {
    echo "====== Running Antrea E2E Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"
    if [[ $TESTBED_TYPE != "kind" ]]; then 
        cp -f "${WORKDIR}/kube.conf" "${WORKDIR}/.kube/config"
    fi
    generate_ssh_config

    set +e
    mkdir -p `pwd`/antrea-test-logs
    # HACK: see https://github.com/antrea-io/antrea/issues/2292
    go mod edit -replace github.com/moby/spdystream=github.com/antoninbas/spdystream@v0.2.1 && go mod tidy
    if [[ $TESTBED_TYPE == "flexible-ipam" ]]; then
        go test -v antrea.io/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs --provider remote -timeout=100m --prometheus --antrea-ipam
    elif [[ $TESTBED_TYPE == "kind" ]]; then
        go test -v antrea.io/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs --provider kind -timeout=100m --prometheus
    else
        go test -v antrea.io/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs --provider remote -timeout=100m --prometheus
    fi
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

    set +e
    if [[ "$TESTCASE" =~ "conformance" ]]; then
        ${WORKSPACE}/ci/run-k8s-e2e-tests.sh --e2e-conformance --e2e-skip "$CONFORMANCE_SKIP" --log-mode $MODE --image-pull-policy ${IMAGE_PULL_POLICY} --kubernetes-version "auto" > ${WORKSPACE}/test-result.log
    else
        ${WORKSPACE}/ci/run-k8s-e2e-tests.sh --e2e-network-policy --e2e-skip "$NETWORKPOLICY_SKIP" --log-mode $MODE --image-pull-policy ${IMAGE_PULL_POLICY} --kubernetes-version "auto" > ${WORKSPACE}/test-result.log
    fi
    set -e

    cat ${WORKSPACE}/test-result.log
    if grep -Fxq "Failed tests:" ${WORKSPACE}/test-result.log; then
        echo "Failed cases exist."
        TEST_FAILURE=true
    else
        echo "All tests passed."
    fi
}

function run_e2e_windows {
    echo "====== Running Antrea e2e Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    clean_for_windows_install_cni
    wait_for_antrea_windows_pods_ready

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"
    cp -f "${WORKDIR}/kube.conf" "${WORKDIR}/.kube/config"
    generate_ssh_config

    set +e
    mkdir -p `pwd`/antrea-test-logs

    echo "====== Run test with e2e test ======"
    go test -v antrea.io/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs --provider remote -timeout=50m --prometheus
    if [[ "$?" != "0" ]]; then
        TEST_FAILURE=true
    fi
    set -e

    tar -zcf antrea-test-logs.tar.gz antrea-test-logs
}

function run_conformance_windows {
    echo "====== Running Antrea Conformance Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    if [[ "$TESTCASE" == "windows-networkpolicy-process" ]]; then
        # Antrea Windows agents are deployed with scripts as processes on host for Windows NetworkPolicy test
        wait_for_antrea_windows_processes_ready
    else
        # Antrea Windows agent Pods are deployed for Windows Conformance test
        clean_for_windows_install_cni
        wait_for_antrea_windows_pods_ready
    fi

    echo "====== Run test with conformance test ======"
    export KUBE_TEST_REPO_LIST=${WORKDIR}/repo_list
    if [ "$TESTCASE" == "windows-networkpolicy" ]; then
        # Allow LinuxOnly mark in windows-networkpolicy because Antrea Windows supports NP functions.
        ginkgo --noColor $E2ETEST_PATH -- --provider=skeleton --ginkgo.focus="$WINDOWS_NETWORKPOLICY_FOCUS" --ginkgo.skip="$WINDOWS_NETWORKPOLICY_SKIP" > windows_conformance_result_no_color.txt || true
    else
        ginkgo --noColor $E2ETEST_PATH -- --provider=skeleton --node-os-distro=windows --ginkgo.focus="$WINDOWS_CONFORMANCE_FOCUS" --ginkgo.skip="$WINDOWS_CONFORMANCE_SKIP" > windows_conformance_result_no_color.txt || true
    fi

    if grep -Fxq "Test Suite Failed" windows_conformance_result_no_color.txt; then
        echo "=== Failed cases exist ==="
        TEST_FAILURE=true
        collect_windows_network_info_and_logs
    else
        echo "All tests passed."
    fi
}

function run_conformance_windows_containerd {
    echo "====== Running Antrea Conformance Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    if [[ "$TESTCASE" == "windows-networkpolicy-process" ]]; then
        # Antrea Windows agents are deployed with scripts as processes on host for Windows NetworkPolicy test
        wait_for_antrea_windows_processes_ready
    else
        # Antrea Windows agent Pods are deployed for Windows Conformance test
        clean_for_windows_install_cni
        wait_for_antrea_windows_pods_ready
    fi

    echo "====== Run test with conformance test ======"
    export KUBE_TEST_REPO_LIST=${WORKDIR}/repo_list
    if [ "$TESTCASE" == "windows-containerd-networkpolicy" ]; then
        # Allow LinuxOnly mark in windows-containerd-networkpolicy because Antrea Windows supports NP functions.
        ginkgo -timeout=3h -p --flake-attempts 3 --no-color $E2ETEST_PATH -- --provider=skeleton --ginkgo.focus="$WINDOWS_NETWORKPOLICY_FOCUS" --ginkgo.skip="$WINDOWS_NETWORKPOLICY_CONTAINERD_SKIP" > windows_conformance_result_no_color.txt || true
    else
        ginkgo --no-color $E2ETEST_PATH -- --provider=skeleton --node-os-distro=windows --ginkgo.focus="$WINDOWS_CONFORMANCE_FOCUS" --ginkgo.skip="$WINDOWS_CONFORMANCE_SKIP" > windows_conformance_result_no_color.txt || true
    fi

    if grep -Fxq "Test Suite Failed" windows_conformance_result_no_color.txt; then
        echo "=== Failed cases exist ==="
        TEST_FAILURE=true
        collect_windows_network_info_and_logs
    else
        echo "All tests passed."
    fi
}

function run_install_windows_ovs {
    echo "===== Verify Install-OVS ====="
    export_govc_env_var
    OVS_VM_NAME="antrea-microsoft-ovs"

    govc snapshot.revert -vm $OVS_VM_NAME initial
    govc vm.power -on $OVS_VM_NAME || true
    echo "===== Testing VM has been reverted and powered on ====="
    IP=$(govc vm.ip $OVS_VM_NAME)
    scp -o StrictHostKeyChecking=no -i ${WORKDIR}/.ssh/id_rsa -T hack/windows/Install-OVS.ps1 Administrator@${IP}:
    ssh -o StrictHostKeyChecking=no -i ${WORKDIR}/.ssh/id_rsa -n Administrator@${IP} '/bin/bash -lc "cp Install-OVS.ps1 C:/k && powershell.exe -File C:/k/Install-OVS.ps1"'

    set +e
    RC_SERVER=$(ssh -o StrictHostKeyChecking=no -i ${WORKDIR}/.ssh/id_rsa -n Administrator@${IP} 'powershell.exe -Command "(get-service ovsdb-server).Status -eq \"Running\""')
    RC_VSWITCHD=$(ssh -o StrictHostKeyChecking=no -i ${WORKDIR}/.ssh/id_rsa -n Administrator@${IP} 'powershell.exe -Command "(get-service ovs-vswitchd).Status -eq \"Running\""')
    set -e

    if [[ $RC_SERVER != *True* || $RC_VSWITCHD != *True* ]]; then
        echo "=== TEST FAILURE !!! ==="
        TEST_FAILURE=true
        ssh -o StrictHostKeyChecking=no -i ${WORKDIR}/.ssh/id_rsa -n Administrator@${IP} "tar zcf openvswitch.tar.gz -C  /cygdrive/c/openvswitch/var/log openvswitch"
        scp -o StrictHostKeyChecking=no -i ${WORKDIR}/.ssh/id_rsa -T Administrator@${IP}:openvswitch.tar.gz .
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

# redeploy_k8s_if_ip_mode_changes redeploys K8s cluster when flexible-ipam is set and existing cluster ip-mode doesn't match input ip-mode
function redeploy_k8s_if_ip_mode_changes() {
    echo "===== Read K8s Node info ====="
    WORKER_HOSTNAMES=()
    HOSTNAMES=()
    WORKER_IPV4S=()
    IPV4S=()
    WORKER_IPV6S=()
    IPV6S=()
    NODE_HOSTNAMES=`cat ${WORKDIR}/nodes | awk '{print $1}'`
    while read HOSTNAME; do
        if [ ${CONTROL_PLANE_HOSTNAME} ]; then
            WORKER_HOSTNAMES+=("${HOSTNAME}")
        else
            CONTROL_PLANE_HOSTNAME=${HOSTNAME}
        fi
        HOSTNAMES+=("${HOSTNAME}")
    done <<< ${NODE_HOSTNAMES}
    NODE_IPV4S=`cat ${WORKDIR}/nodes | awk '{print $2}'`
    while read IPV4; do
        if [ ${CONTROL_PLANE_IPV4} ]; then
            WORKER_IPV4S+=("${IPV4}")
        else
            CONTROL_PLANE_IPV4=${IPV4}
        fi
        IPV4S+=("${IPV4}")
    done <<< ${NODE_IPV4S}
    NODE_IPV6S=`cat ${WORKDIR}/nodes | awk '{print $3}'`
    while read IPV6; do
        if [ ${CONTROL_PLANE_IPV6} ]; then
            WORKER_IPV6S+=("${IPV6}")
        else
            CONTROL_PLANE_IPV6=${IPV6}
        fi
        IPV6S+=("${IPV6}")
    done <<< ${NODE_IPV6S}

    echo "===== Check K8s cluster status ====="
    INITIAL_VALUE=10
    HAS_IPV4=${INITIAL_VALUE}
    HAS_IPV6=${INITIAL_VALUE}
    POD_CIDRS=($( (kubectl get node ${CONTROL_PLANE_HOSTNAME} -o json | jq -r '.spec.podCIDRs | @sh') | tr -d \'\")) || true
    echo "POD_CIDRS=${POD_CIDRS[*]}"
    for POD_CIDR in "${POD_CIDRS[@]}"; do
        if [[ $POD_CIDR =~ .*:.* ]]
        then
            (( HAS_IPV6++ ))
        else
            (( HAS_IPV4++ ))
        fi
    done
    if [[ ${IP_MODE} == "ipv4" ]]; then
        (( HAS_IPV4-- ))
    elif [[ ${IP_MODE} == "ipv6" ]]; then
        (( HAS_IPV6-- ))
    else
        (( HAS_IPV4-- ))
        (( HAS_IPV6-- ))
    fi
    if [ ${HAS_IPV4} -eq ${INITIAL_VALUE} ] && [ ${HAS_IPV6} -eq ${INITIAL_VALUE} ]; then
      return 0
    fi

    echo "===== Reset K8s cluster Nodes ====="
    for IPV4 in "${IPV4S[@]}"; do
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${IPV4} "sudo kubeadm reset -f; sudo netplan apply; sudo ip link set br-int down || true"
    done

    echo "===== Redeploy K8s utils ====="
    sudo apt update < /dev/null
    sudo apt remove -y kubectl < /dev/null
    sudo apt install -y kubectl=${K8S_VERSION} < /dev/null
    for IPV4 in "${IPV4S[@]}"; do
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${IPV4} "sudo apt update < /dev/null; sudo apt remove -y kubectl kubelet kubeadm < /dev/null; sudo apt install -y kubectl=${K8S_VERSION} kubelet=${K8S_VERSION} kubeadm=${K8S_VERSION} < /dev/null"
    done

    echo "===== Configure kubelet ====="
    for (( i=0; i<${#IPV4S[@]}; i++ )); do
        NODE_IP_STRING=""
        if [[ ${IP_MODE} == "ipv4" ]]; then
            NODE_IP_STRING=${IPV4S[i]}
        elif [[ ${IP_MODE} == "ipv6" ]]; then
            NODE_IP_STRING=${IPV6S[i]}
        else
            NODE_IP_STRING="${IPV4S[i]},${IPV6S[i]}"
        fi
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${IPV4S[i]} "echo \"KUBELET_EXTRA_ARGS=--node-ip=${NODE_IP_STRING}\" | sudo tee /etc/default/kubelet; sudo systemctl restart kubelet"
    done

    echo "===== Set up K8s cluster ====="
    TOKEN=`ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${CONTROL_PLANE_IPV4} "kubeadm token generate"`
    echo "===== Generated K8s cluster token ${TOKEN} ====="
    POD_SUBNET_IPV4="192.168.248.0/21"
    POD_SUBNET_IPV6="fd02:0:0:f8::/61"
    SERVICE_SUBNET_IPV4="10.96.0.0/16"
    SERVICE_SUBNET_IPV6="2001:db8:42:1::/112"
    POD_SUBNET_STRING=""
    SERVICE_SUBNET_STRING=""
    ADVERTISE_ADDRESS_STRING=""
    FEATURE_GATES_STRING=""
    if [[ ${IP_MODE} == "ipv4" ]]; then
        POD_SUBNET_STRING=${POD_SUBNET_IPV4}
        SERVICE_SUBNET_STRING=${SERVICE_SUBNET_IPV4}
        ADVERTISE_ADDRESS_STRING=${CONTROL_PLANE_IPV4}
        APISERVER_IP_STRING=${ADVERTISE_ADDRESS_STRING}
    elif [[ ${IP_MODE} == "ipv6" ]]; then
        POD_SUBNET_STRING=${POD_SUBNET_IPV6}
        SERVICE_SUBNET_STRING=${SERVICE_SUBNET_IPV6}
        ADVERTISE_ADDRESS_STRING=${CONTROL_PLANE_IPV6}
        APISERVER_IP_STRING="[${ADVERTISE_ADDRESS_STRING}]"
    else
        POD_SUBNET_STRING="${POD_SUBNET_IPV4},${POD_SUBNET_IPV6}"
        SERVICE_SUBNET_STRING="${SERVICE_SUBNET_IPV4},${SERVICE_SUBNET_IPV6}"
        ADVERTISE_ADDRESS_STRING=${CONTROL_PLANE_IPV4}
        if [[ ${K8S_VERSION} =~ 1.19. ]] || [[ ${K8S_VERSION} =~ 1.20. ]]; then
          FEATURE_GATES_STRING=`echo -e "featureGates:\n  IPv6DualStack: true"`
        fi
        APISERVER_IP_STRING=${ADVERTISE_ADDRESS_STRING}
    fi
    cat <<EOF | tee ${WORKDIR}/kubeadm.conf
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- groups:
  token: ${TOKEN}
nodeRegistration:
  name: "${CONTROL_PLANE_HOSTNAME}"
localAPIEndpoint:
  advertiseAddress: "${ADVERTISE_ADDRESS_STRING}"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
${FEATURE_GATES_STRING}
networking:
  podSubnet: "${POD_SUBNET_STRING}"
  serviceSubnet: "${SERVICE_SUBNET_STRING}"
apiServer:
  certSANs:
  - "${ADVERTISE_ADDRESS_STRING}"
EOF
    scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" ${WORKDIR}/kubeadm.conf ubuntu@${CONTROL_PLANE_IPV4}:${WORKDIR}/kubeadm.conf
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${CONTROL_PLANE_IPV4} "sudo kubeadm init --config ${WORKDIR}/kubeadm.conf"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${CONTROL_PLANE_IPV4} "mkdir -p \$HOME/.kube"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${CONTROL_PLANE_IPV4} "sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${CONTROL_PLANE_IPV4} "sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n jenkins@${CONTROL_PLANE_IPV4} "mkdir -p \$HOME/.kube"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${CONTROL_PLANE_IPV4} "sudo cp -f /etc/kubernetes/admin.conf \`getent passwd jenkins | cut -d: -f6\`/.kube/config"
    ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${CONTROL_PLANE_IPV4} "sudo chown jenkins:jenkins \`getent passwd jenkins | cut -d: -f6\`/.kube/config"
    for WORKER_IPV4 in "${WORKER_IPV4S[@]}"; do
        ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" -n ubuntu@${WORKER_IPV4} "sudo kubeadm join ${APISERVER_IP_STRING}:6443 --token ${TOKEN} --discovery-token-unsafe-skip-ca-verification"
    done
    mkdir -p $HOME/.kube
    scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/id_rsa" ubuntu@${CONTROL_PLANE_IPV4}:\$HOME/.kube/config ${WORKDIR}/.kube/
    cp -f "${WORKDIR}/.kube/config" "${WORKDIR}/kube.conf"

    echo "===== Configure routes ====="
    sudo ip route flush root ${POD_SUBNET_IPV4}
    sudo ip -6 route flush root ${POD_SUBNET_IPV6}
    for (( i=0; i<${#HOSTNAMES[@]}; i++ )); do
        POD_CIDRS=($( (kubectl get node ${HOSTNAMES[i]} -o json | jq -r '.spec.podCIDRs | @sh') | tr -d \'\"))
        for POD_CIDR in "${POD_CIDRS[@]}"; do
            if [[ $POD_CIDR =~ .*:.* ]]
            then
                sudo ip -6 route add ${POD_CIDR} via ${IPV6S[i]}
            else
                sudo ip route add ${POD_CIDR} via ${IPV4S[i]}
            fi
        done
    done
}

export KUBECONFIG=${KUBECONFIG_PATH}
if [[ $TESTBED_TYPE == "flexible-ipam" ]]; then
    ./hack/generate-manifest.sh --flexible-ipam --multicast --verbose-log > build/yamls/antrea.yml
fi

if [[ $TESTCASE =~ "multicast" ]]; then
    ./hack/generate-manifest.sh --encap-mode noEncap --multicast --multicast-interfaces "ens224" --verbose-log > build/yamls/antrea.yml
fi

source $WORKSPACE/ci/jenkins/utils.sh
check_and_upgrade_golang
clean_tmp
if [[ ${TESTCASE} == "windows-install-ovs" ]]; then
    run_install_windows_ovs
    if [[ ${TEST_FAILURE} == true ]]; then
        exit 1
    fi
    exit 0
fi

trap clean_antrea EXIT
if [[ ${TESTCASE} =~ "windows" ]]; then
    if [[ ${TESTCASE} =~ "containerd" ]]; then
        WINDOWS_YAML_SUFFIX="windows-containerd-with-ovs"
        build_and_deliver_antrea_windows_and_linux_containerd_images
        if [[ ${TESTCASE} =~ "e2e" ]]; then
            run_e2e_windows
        else
            run_conformance_windows_containerd
        fi
    else
        build_and_deliver_antrea_windows_and_linux_docker_images
        if [[ ${TESTCASE} =~ "e2e" ]]; then
            run_e2e_windows
        else
            run_conformance_windows
        fi
    fi
elif [[ ${TESTCASE} =~ "e2e" ]]; then
    deliver_antrea
    run_e2e
else
    deliver_antrea
    run_conformance
fi

if [[ ${TEST_FAILURE} == true ]]; then
    exit 1
fi
