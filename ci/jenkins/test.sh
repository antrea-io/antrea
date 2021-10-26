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

DEFAULT_WORKDIR="/var/lib/jenkins"
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/kube.conf
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
TESTCASE=""
TEST_FAILURE=false
MODE="report"
DOCKER_REGISTRY=$(head -n1 "${WORKSPACE}/ci/docker-registry")
GO_VERSION=$(head -n1 "${WORKSPACE}/build/images/deps/go-version")
IMAGE_PULL_POLICY="Always"
PROXY_ALL=false
FLEXIBLE_IPAM=false

WINDOWS_CONFORMANCE_FOCUS="\[sig-network\].+\[Conformance\]|\[sig-windows\]"
WINDOWS_CONFORMANCE_SKIP="\[LinuxOnly\]|\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]|\[Privileged\]|should be able to change the type from|\[sig-network\] Services should be able to create a functioning NodePort service \[Conformance\]|Service endpoints latency should not be very high|should be able to create a functioning NodePort service for Windows"
WINDOWS_NETWORKPOLICY_FOCUS="\[Feature:NetworkPolicy\]"
WINDOWS_NETWORKPOLICY_SKIP="SCTP"
CONFORMANCE_SKIP="\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]"
NETWORKPOLICY_SKIP="should allow egress access to server in CIDR block|should enforce except clause while egress access to server in CIDR block"

# TODO: change to "control-plane" when testbeds are updated to K8s v1.20
CONTROL_PLANE_NODE_ROLE="master"

CLEAN_STALE_IMAGES="docker system prune --force --all --filter until=48h"

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--testcase <windows-install-ovs|windows-conformance|windows-networkpolicy|windows-e2e|e2e|conformance|networkpolicy>]

Run K8s e2e community tests (Conformance & Network Policy) or Antrea e2e tests on a remote (Jenkins) Windows or Linux cluster.

        --kubeconfig             Path of cluster kubeconfig.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase               Windows install OVS, Conformance and Network Policy or Antrea e2e testcases on a Windows or Linux cluster. It can also be flexible ipam e2e test.
        --registry               The docker registry to use instead of dockerhub.
        --proxyall               Enable proxyAll to test AntreaProxy.
        --flexible-ipam          Run tests in flexible ipam mode"

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
    --testcase)
    TESTCASE="$2"
    shift 2
    ;;
    --registry)
    DOCKER_REGISTRY="$2"
    shift 2
    ;;
    --proxyall)
    PROXY_ALL=true
    shift
    ;;
    --flexible-ipam)
    FLEXIBLE_IPAM=true
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
    export GOVC_URL=$GOVC_URL
    export GOVC_USERNAME=$GOVC_USERNAME
    export GOVC_PASSWORD=$GOVC_PASSWORD
    export GOVC_INSECURE=1
    export GOVC_DATACENTER=$GOVC_DATACENTER
    export GOVC_DATASTORE=$GOVC_DATASTORE
}

function clean_antrea {
    echo "====== Cleanup Antrea Installation ======"
    clean_up_one_ns "antrea-ipam-test"
    clean_up_one_ns "antrea-test"
    kubectl get pod -n kube-system -l component=antrea-agent --no-headers=true | awk '{print $1}' | while read AGENTNAME; do
        kubectl exec $AGENTNAME -c antrea-agent -n kube-system -- ovs-vsctl del-port br-int gw0 || true
    done
    for antrea_yml in ${WORKDIR}/*.yml; do
        kubectl delete -f $antrea_yml --ignore-not-found=true || true
    done
}

function clean_for_windows_install_cni {
    # https://github.com/antrea-io/antrea/issues/1577
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $6}' | while read IP; do
        CLEAN_LIST=("/cygdrive/c/opt/cni/bin/antrea.exe" "/cygdrive/c/opt/cni/bin/host-local.exe" "/cygdrive/c/k/antrea/etc/antrea-agent.conf" "/cygdrive/c/etc/cni/net.d/10-antrea.conflist" "/cygdrive/c/k/antrea/bin/antrea-agent.exe")
        for file in "${CLEAN_LIST[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -f ${file}"
        done
    done
}

function collect_windows_network_info_and_logs {
    echo "=== Collecting information after failure ==="
    DEBUG_LOG_PATH="debug_logs"
    mkdir "${DEBUG_LOG_PATH}"
    kubectl get pod -n kube-system -l component=antrea-agent --no-headers=true | awk '{print $1}' | while read AGENTNAME; do
        IP=$(kubectl get pod ${AGENTNAME} -n kube-system -o json | jq -r '.status.hostIP')
        mkdir "${DEBUG_LOG_PATH}/${AGENTNAME}"

        echo "=== Collecting '${AGENTNAME}' agent network info after failure ==="
        AGENT_NETWORK_INFO_PATH="${DEBUG_LOG_PATH}/${AGENTNAME}/network_info"
        mkdir "${AGENT_NETWORK_INFO_PATH}"
        if [[ "${AGENTNAME}" =~ "windows" ]]; then
            ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ovs-ofctl dump-flows br-int" > "${AGENT_NETWORK_INFO_PATH}/flows" || true
            ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ovs-vsctl show" > "${AGENT_NETWORK_INFO_PATH}/db" || true
            ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ipconfig" > "${AGENT_NETWORK_INFO_PATH}/addrs" || true
        else
            kubectl exec "${AGENTNAME}" -c antrea-agent -n kube-system -- ovs-ofctl dump-flows br-int > "${AGENT_NETWORK_INFO_PATH}/flows" || true
            kubectl exec "${AGENTNAME}" -c antrea-agent -n kube-system -- ovs-vsctl show > "${AGENT_NETWORK_INFO_PATH}/db" || true
            kubectl exec "${AGENTNAME}" -c antrea-agent -n kube-system -- ip a > "${AGENT_NETWORK_INFO_PATH}/addrs" || true
        fi

        echo "=== Collecting '${AGENTNAME}' antrea agent log after failure ==="
        ANTREA_AGENT_LOG_PATH="${DEBUG_LOG_PATH}/${AGENTNAME}/antrea_agent_log"
        mkdir "${ANTREA_AGENT_LOG_PATH}"
        kubectl logs "${AGENTNAME}" -n kube-system -c antrea-agent > "${ANTREA_AGENT_LOG_PATH}/antrea-agent.log" || true
        if [[ "${AGENTNAME}" =~ "windows" ]]; then
            echo "Windows agent doesn't have antrea-ovs container"
        else
            kubectl logs "${AGENTNAME}" -n kube-system -c antrea-ovs > "${ANTREA_AGENT_LOG_PATH}/antrea-ovs.log" || true
        fi
    done

    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $1}' | while read NODENAME; do
        IP=$(kubectl get node ${NODENAME} -o json | jq -r '.status.addresses[] | select(.type | test("InternalIP")).address')
        mkdir "${DEBUG_LOG_PATH}/${NODENAME}"

        echo "=== Collecting '${NODENAME}' Node network info after failure ==="
        NODE_NETWORK_INFO_PATH="${DEBUG_LOG_PATH}/${NODENAME}/network_info"
        mkdir "${NODE_NETWORK_INFO_PATH}"
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "powershell.exe get-NetAdapter" > "${NODE_NETWORK_INFO_PATH}/adapters" || true
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "ipconfig.exe" > "${NODE_NETWORK_INFO_PATH}/ipconfig" || true
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "powershell.exe Get-HNSNetwork" > "${NODE_NETWORK_INFO_PATH}/hns_network" || true
        ssh -o StrictHostKeyChecking=no -n administrator@${IP} "powershell.exe Get-HNSEndpoint" > "${NODE_NETWORK_INFO_PATH}/hns_endpoint" || true

        echo "=== Collecting '${NODENAME}' kubelet and docker logs after failure ==="
        KUBELET_LOG_PATH="${DEBUG_LOG_PATH}/${NODENAME}/kubelet"
        mkdir "${KUBELET_LOG_PATH}"
        scp -q -o StrictHostKeyChecking=no -T administrator@${IP}:/cygdrive/c/var/log/kubelet/* "${KUBELET_LOG_PATH}"

        DOCKER_LOG_PATH="${DEBUG_LOG_PATH}/${NODENAME}/docker"
        mkdir "${DOCKER_LOG_PATH}"
        scp -q -o StrictHostKeyChecking=no -T administrator@${IP}:'/cygdrive/c/"Program Files"/Docker/dockerd.log*' "${DOCKER_LOG_PATH}"
    done
    tar zcf debug_logs.tar.gz "${DEBUG_LOG_PATH}"
}

function wait_for_antrea_windows_pods_ready {
    kubectl apply -f "${WORKDIR}/antrea.yml"
    if [[ "${PROXY_ALL}" == false ]]; then
        kubectl apply -f "${WORKDIR}/kube-proxy-windows.yml"
    fi
    kubectl apply -f "${WORKDIR}/antrea-windows.yml"
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status deployment/coredns -n kube-system
    kubectl rollout status deployment.apps/antrea-controller -n kube-system
    kubectl rollout status daemonset/antrea-agent -n kube-system
    kubectl rollout status daemonset.apps/antrea-agent-windows -n kube-system
    if [[ "${PROXY_ALL}" == false ]]; then
        kubectl rollout status daemonset/kube-proxy-windows -n kube-system
    fi
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $6}' | while read IP; do
        for i in `seq 5`; do
            sleep 5
            timeout 5s ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell Get-NetAdapter -Name br-int -ErrorAction SilentlyContinue" && break
        done
        sleep 10
    done
}

function wait_for_antrea_windows_processes_ready {
    kubectl apply -f "${WORKDIR}/antrea.yml"
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status deployment/coredns -n kube-system
    kubectl rollout status deployment.apps/antrea-controller -n kube-system
    kubectl rollout status daemonset/antrea-agent -n kube-system
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $6}' | while read IP; do
        echo "===== Run script to startup Antrea agent ====="
        ANTREA_VERSION=$(ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "/cygdrive/c/k/antrea/bin/antrea-agent.exe --version" | awk '{print $3}')
        ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "chmod +x /cygdrive/c/k/antrea/Start.ps1 && powershell 'c:\k\antrea\Start.ps1 -AntreaVersion ${ANTREA_VERSION}'"
        for i in `seq 5`; do
            sleep 5
            timeout 5s ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell Get-NetAdapter -Name br-int -ErrorAction SilentlyContinue" && break
        done
        sleep 10
    done
}

function clean_up_one_ns {
    ns=$1
    kubectl get pod -n "${ns}" --no-headers=true | awk '{print $1}' | while read pod_name; do
        kubectl delete pod "${pod_name}" -n "${ns}" --force --grace-period 0
    done
    kubectl delete ns "${ns}" --ignore-not-found=true || true
}

function deliver_antrea_windows {
    echo "====== Cleanup Antrea Installation ======"
    clean_up_one_ns "antrea-test"
    kubectl delete -f ${WORKDIR}/antrea-windows.yml --ignore-not-found=true || true
    kubectl delete -f ${WORKDIR}/kube-proxy-windows.yml --ignore-not-found=true || true
    kubectl delete daemonset antrea-agent -n kube-system --ignore-not-found=true || true
    kubectl delete -f ${WORKDIR}/antrea.yml --ignore-not-found=true || true

    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKSPACE}/../gocache
    export PATH=${GOROOT}/bin:$PATH

    git show --numstat
    make clean
    ${CLEAN_STALE_IMAGES}
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-ubuntu-all.sh --pull
    if [[ "$TESTCASE" == "windows-networkpolicy-process" ]]; then
        make windows-bin
        make antctl-windows
    fi

    echo "====== Delivering Antrea to all the Nodes ======"
    export_govc_env_var

    if [[ "${PROXY_ALL}" == true ]]; then
        echo "====== Updating yaml files to enable proxyAll ======"
        KUBERNETES_SVC_EP_IP=$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[0].ip}')
        KUBERNETES_SVC_EP_PORT=$(kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].ports[0].port}')
        KUBERNETES_SVC_EP_ADDR="${KUBERNETES_SVC_EP_IP}:${KUBERNETES_SVC_EP_PORT}"
        sed -i "s|#kubeAPIServerOverride: \"\"|kubeAPIServerOverride: \"${KUBERNETES_SVC_EP_ADDR}\"|g" build/yamls/antrea.yml build/yamls/antrea-windows.yml
        sed -i "s|#proxyAll: false|proxyAll: true|g" build/yamls/antrea.yml build/yamls/antrea-windows.yml
    fi

    cp -f build/yamls/*.yml $WORKDIR
    docker save -o antrea-ubuntu.tar projects.registry.vmware.com/antrea/antrea-ubuntu:latest

    echo "===== Pull necessary images on Control-Plane node ====="
    harbor_images=("agnhost:2.13" "nginx:1.15-alpine")
    antrea_images=("e2eteam/agnhost:2.13" "docker.io/library/nginx:1.15-alpine")
    for i in "${!harbor_images[@]}"; do
        docker pull -q "${DOCKER_REGISTRY}/antrea/${harbor_images[i]}"
        docker tag "${DOCKER_REGISTRY}/antrea/${harbor_images[i]}" "${antrea_images[i]}"
    done
    echo "===== Deliver Antrea to Linux worker nodes and pull necessary images on worker nodes ====="
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 !~ /win/ {print $6}' | while read IP; do
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar jenkins@${IP}:${WORKDIR}/antrea-ubuntu.tar
        ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES}; docker load -i ${WORKDIR}/antrea-ubuntu.tar" || true

        harbor_images=("agnhost:2.13" "nginx:1.15-alpine")
        antrea_images=("e2eteam/agnhost:2.13" "docker.io/library/nginx:1.15-alpine")
        for i in "${!harbor_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker pull -q ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} && docker tag ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} ${antrea_images[i]}" || true
        done
    done

    echo "===== Deliver Antrea Windows to Windows worker nodes and pull necessary images on Windows worker nodes ====="
    rm -f antrea-windows.tar.gz
    sed -i 's/if (!(Test-Path $AntreaAgentConfigPath))/if ($true)/' hack/windows/Helper.psm1
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $1}' | while read WORKER_NAME; do
        echo "==== Reverting Windows VM ${WORKER_NAME} ====="
        govc snapshot.revert -vm ${WORKER_NAME} win-initial
        # If Windows VM fails to power on correctly in time, retry several times.
        winVMIPs=""
        for i in `seq 3`; do
            winVMIPs=$(govc vm.ip -wait=1m -a ${WORKER_NAME})
            if [[ $winVMIPs != "" ]]; then
                echo "Windows VM ${WORKER_NAME} powered on"
                break
            fi
            echo "Windows VM ${WORKER_NAME} failed to power on"
            govc vm.power -on ${WORKER_NAME} || true
        done
        if [[ $winVMIPs == "" ]]; then
            echo "Windows VM ${WORKER_NAME} didn't power on after 3 tries, exiting"
            exit 1
        fi
        IP=$(kubectl get node "${WORKER_NAME}" -o jsonpath='{.status.addresses[0].address}')
        # Windows VM is reverted to an old snapshot so computer date needs updating.
        for i in `seq 24`; do
            sleep 5
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "W32tm /resync /force" | grep successfully && break
        done
        # Some tests need us.gcr.io/k8s-artifacts-prod/e2e-test-images/agnhost:2.13 image but it is not for windows/amd64 10.0.17763
        # Use e2eteam/agnhost:2.13 instead
        harbor_images=("sigwindowstools-kube-proxy:v1.18.0" "agnhost:2.13" "agnhost:2.13" "e2eteam-jessie-dnsutils:1.0" "e2eteam-pause:3.2")
        antrea_images=("sigwindowstools/kube-proxy:v1.18.0" "e2eteam/agnhost:2.13" "us.gcr.io/k8s-artifacts-prod/e2e-test-images/agnhost:2.13" "e2eteam/jessie-dnsutils:1.0" "e2eteam/pause:3.2")
        for i in "${!harbor_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull -q ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} && docker tag ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} ${antrea_images[i]}" || true
        done

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
            scp -o StrictHostKeyChecking=no -T bin/antctl-windows.exe Administrator@${IP}:/cygdrive/c/k/antrea/bin/antctl.exe
            scp -o StrictHostKeyChecking=no -T bin/antrea-cni.exe Administrator@${IP}:/cygdrive/c/opt/cni/bin/antrea.exe
            scp -o StrictHostKeyChecking=no -T hack/windows/Start.ps1 Administrator@${IP}:/cygdrive/c/k/antrea/
            scp -o StrictHostKeyChecking=no -T hack/windows/Stop.ps1 Administrator@${IP}:/cygdrive/c/k/antrea/
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
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/golang:${GO_VERSION} && docker tag ${DOCKER_REGISTRY}/antrea/golang:${GO_VERSION} golang:${GO_VERSION}"
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -rf antrea && mkdir antrea && cd antrea && tar -xzf ../antrea_repo.tar.gz > /dev/null && sed -i \"s|build/images/Dockerfile.build.windows|build/images/Dockerfile.build.windows --network host|g\" Makefile && NO_PULL=${NO_PULL} make build-windows && docker save -o antrea-windows.tar ${DOCKER_REGISTRY}/antrea/antrea-windows:latest && gzip -f antrea-windows.tar" || true
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
    done
    rm -f antrea-windows.tar.gz
}

function deliver_antrea {
    echo "====== Cleanup Antrea Installation ======"
    clean_up_one_ns "antrea-ipam-test"
    clean_up_one_ns "antrea-test"
    kubectl delete daemonset antrea-agent -n kube-system || true
    kubectl delete -f ${WORKDIR}/antrea.yml || true

    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE="${WORKSPACE}/../gocache"
    export PATH=${GOROOT}/bin:$PATH

    git show --numstat
    make clean
    ${CLEAN_STALE_IMAGES}
    if [[ ! "${TESTCASE}" =~ "e2e" && "${DOCKER_REGISTRY}" != "" ]]; then
        docker pull "${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3"
        docker tag "${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3" "sonobuoy/systemd-logs:v0.3"
    fi
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-ubuntu-all.sh --pull
    make flow-aggregator-image

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

    if [[ $FLEXIBLE_IPAM == true ]]; then
        control_plane_ip="$(kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 == role {print $6}')"
        scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" build/yamls/*.yml jenkins@${control_plane_ip}:~
    else
        cp -f build/yamls/*.yml $WORKDIR
    fi

    echo "====== Delivering Antrea to all the Nodes ======"
    docker save -o antrea-ubuntu.tar projects.registry.vmware.com/antrea/antrea-ubuntu:latest
    docker save -o flow-aggregator.tar projects.registry.vmware.com/antrea/flow-aggregator:latest

    if [[ $FLEXIBLE_IPAM == true ]]; then
        kubectl get nodes -o wide --no-headers=true | awk '{print $6}' | while read IP; do
            scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" antrea-ubuntu.tar jenkins@${IP}:${DEFAULT_WORKDIR}/antrea-ubuntu.tar
            scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" flow-aggregator.tar jenkins@${IP}:${DEFAULT_WORKDIR}/flow-aggregator.tar
            ssh -o StrictHostKeyChecking=no -i "${WORKDIR}/jenkins_id_rsa" -n jenkins@${IP} "${CLEAN_STALE_IMAGES}; docker load -i ${DEFAULT_WORKDIR}/antrea-ubuntu.tar; docker load -i ${DEFAULT_WORKDIR}/flow-aggregator.tar" || true
            if [[ ! "${TESTCASE}" =~ "e2e" && "${DOCKER_REGISTRY}" != "" ]]; then
                ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3 ; docker tag ${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3 sonobuoy/systemd-logs:v0.3"
            fi
        done
    else
        kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role {print $6}' | while read IP; do
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar jenkins@[${IP}]:${WORKDIR}/antrea-ubuntu.tar
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" flow-aggregator.tar jenkins@[${IP}]:${WORKDIR}/flow-aggregator.tar
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES}; docker load -i ${WORKDIR}/antrea-ubuntu.tar; docker load -i ${WORKDIR}/flow-aggregator.tar" || true
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
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"
    cp -f "${WORKDIR}/kube.conf" "${WORKDIR}/.kube/config"
    generate_ssh_config

    set +e
    mkdir -p `pwd`/antrea-test-logs
    # HACK: see https://github.com/antrea-io/antrea/issues/2292
    go mod edit -replace github.com/moby/spdystream=github.com/antoninbas/spdystream@v0.2.1 && go mod tidy
    if [[ $FLEXIBLE_IPAM == true ]]; then
        go test -v antrea.io/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs --provider remote -timeout=100m --prometheus --antrea-ipam
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
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    kubectl apply -f build/yamls/antrea.yml
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status deployment/coredns -n kube-system
    kubectl rollout status deployment.apps/antrea-controller -n kube-system
    kubectl rollout status daemonset/antrea-agent -n kube-system

    if [[ "$TESTCASE" =~ "conformance" ]]; then
        ${WORKSPACE}/ci/run-k8s-e2e-tests.sh --e2e-conformance --e2e-skip "$CONFORMANCE_SKIP" --log-mode $MODE --image-pull-policy ${IMAGE_PULL_POLICY} --kube-conformance-image-version "auto" > ${WORKSPACE}/test-result.log
    else
        ${WORKSPACE}/ci/run-k8s-e2e-tests.sh --e2e-network-policy --e2e-skip "$NETWORKPOLICY_SKIP" --log-mode $MODE --image-pull-policy ${IMAGE_PULL_POLICY} --kube-conformance-image-version "auto" > ${WORKSPACE}/test-result.log
    fi

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
    export GOROOT=/usr/local/go
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
    export GOROOT=/usr/local/go
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

    echo "====== Run test with e2e.test ======"
    export KUBE_TEST_REPO_LIST=${WORKDIR}/repo_list
    if [ "$TESTCASE" == "windows-networkpolicy" ]; then
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

export KUBECONFIG=${KUBECONFIG_PATH}
if [[ $FLEXIBLE_IPAM == true ]]; then
    ./hack/generate-manifest.sh --flexible-ipam > build/yamls/antrea.yml
fi

clean_tmp
if [[ ${TESTCASE} == "windows-install-ovs" ]]; then
    run_install_windows_ovs
    if [[ ${TEST_FAILURE} == true ]]; then
        exit 1
    fi
    exit 0
fi

#trap clean_antrea EXIT
if [[ ${TESTCASE} =~ "windows" ]]; then
    deliver_antrea_windows
    if [[ ${TESTCASE} =~ "e2e" ]]; then
        run_e2e_windows
    else
        run_conformance_windows
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
