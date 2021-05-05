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
IMAGE_PULL_POLICY="Always"

WINDOWS_CONFORMANCE_FOCUS="\[sig-network\].+\[Conformance\]|\[sig-windows\]"
WINDOWS_CONFORMANCE_SKIP="\[LinuxOnly\]|\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]|\[Privileged\]|should be able to change the type from|\[sig-network\] Services should be able to create a functioning NodePort service \[Conformance\]|Service endpoints latency should not be very high"
WINDOWS_NETWORKPOLICY_FOCUS="\[Feature:NetworkPolicy\]"
WINDOWS_NETWORKPOLICY_SKIP="SKIP_NO_TESTCASE"
CONFORMANCE_SKIP="\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]"
NETWORKPOLICY_SKIP="should allow egress access to server in CIDR block|should enforce except clause while egress access to server in CIDR block"

# TODO: change to "control-plane" when testbeds are updated to K8s v1.20
CONTROL_PLANE_NODE_ROLE="master"

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--testcase <windows-install-ovs|windows-conformance|windows-networkpolicy|windows-e2e|e2e|conformance|networkpolicy>]

Run K8s e2e community tests (Conformance & Network Policy) or Antrea e2e tests on a remote (Jenkins) Windows or Linux cluster.

        --kubeconfig             Path of cluster kubeconfig.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase               Windows install OVS, Conformance and Network Policy or Antrea e2e testcases on a Windows or Linux cluster.
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
    kubectl delete ns antrea-test || true
    kubectl get pod -n kube-system -l component=antrea-agent --no-headers=true | awk '{print $1}' | while read AGENTNAME; do
        kubectl exec $AGENTNAME -c antrea-agent -n kube-system -- ovs-vsctl del-port br-int gw0 || true
    done
    for antrea_yml in ${WORKDIR}/*.yml; do
        kubectl delete -f $antrea_yml --ignore-not-found=true || true
    done
}

function clean_for_windows_install_cni {
    # https://github.com/vmware-tanzu/antrea/issues/1577
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $6}' | while read IP; do
        CLEAN_LIST=("/cygdrive/c/opt/cni/bin/antrea.exe" "/cygdrive/c/opt/cni/bin/host-local.exe" "/cygdrive/c/k/antrea/etc/antrea-agent.conf" "/cygdrive/c/etc/cni/net.d/10-antrea.conflist" "/cygdrive/c/k/antrea/bin/antrea-agent.exe")
        for file in "${CLEAN_LIST[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -f ${file}"
        done
    done
}

function collect_windows_network_info_and_logs {
    echo "=== Collecting network info after failure ==="
    mkdir network_info
    kubectl get pod -n kube-system -l component=antrea-agent --no-headers=true | awk '{print $1}' | while read AGENTNAME; do
        mkdir network_info/${AGENTNAME}
        kubectl exec "$AGENTNAME" -c antrea-agent -n kube-system -- ovs-ofctl dump-flows br-int > "network_info/${AGENTNAME}/flows" || true
        kubectl exec "$AGENTNAME" -c antrea-agent -n kube-system -- ovs-vsctl show > "network_info/$AGENTNAME/db" || true
        kubectl exec "$AGENTNAME" -c antrea-agent -n kube-system -- ip a > "network_info/${AGENTNAME}/addrs" || true
    done
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $6}' | while read IP; do
        mkdir network_info/${IP}
        ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell.exe get-NetAdapter" > "network_info/${IP}/adapters" || true
        ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "ipconfig.exe" > "network_info/${IP}/ipconfig" || true
        ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell.exe Get-HNSNetwork" > "network_info/${IP}/hns_network" || true
        ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell.exe Get-HNSEndpoint" > "network_info/${IP}/hns_endpoint" || true
    done
    tar zcf network_info.tar.gz network_info

    echo "=== Collecting antrea agent log after failure ==="
    mkdir antrea_agent_log
    kubectl get pod -n kube-system -l component=antrea-agent --no-headers=true | awk '{print $1}' | while read AGENTNAME; do
        mkdir antrea_agent_log/$AGENTNAME
        kubectl logs $AGENTNAME -n kube-system -c antrea-agent > antrea_agent_log/$AGENTNAME/antrea-agent.log || true
        kubectl logs $AGENTNAME -n kube-system -c antrea-ovs > antrea_agent_log/$AGENTNAME/antrea-ovs.log || true
    done
    tar zcf antrea_agent_log.tar.gz antrea_agent_log
}

function wait_for_antrea_windows_pods_ready {
    kubectl apply -f "${WORKDIR}/build/yamls/antrea.yml"
    kubectl apply -f "${WORKDIR}/kube-proxy-windows.yml"
    kubectl apply -f "${WORKDIR}/build/yamls/antrea-windows.yml"
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status deployment/coredns -n kube-system
    kubectl rollout status deployment.apps/antrea-controller -n kube-system
    kubectl rollout status daemonset/antrea-agent -n kube-system
    kubectl rollout status daemonset.apps/antrea-agent-windows -n kube-system
    kubectl rollout status daemonset/kube-proxy-windows -n kube-system
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $6}' | while read IP; do
        for i in `seq 5`; do
            sleep 5
            timeout 5s ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell Get-NetAdapter -Name br-int -ErrorAction SilentlyContinue" && break
        done
        sleep 10
    done
}

function wait_for_antrea_windows_processes_ready {
    kubectl apply -f "${WORKDIR}/build/yamls/antrea.yml"
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

function deliver_antrea_windows {
    echo "====== Cleanup Antrea Installation ======"
    export KUBECONFIG=$KUBECONFIG_PATH
    kubectl delete ns antrea-test --ignore-not-found=true || true
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
    docker images | grep 'antrea-ubuntu' | awk '{print $3}' | xargs -r docker rmi -f || true
    docker images | grep '<none>' | awk '{print $3}' | xargs -r docker rmi || true
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-ubuntu-all.sh --pull
    if [[ "$TESTCASE" =~ "networkpolicy" ]]; then
        make windows-bin
    fi

    echo "====== Delivering Antrea to all the Nodes ======"
    export KUBECONFIG=$KUBECONFIG_PATH
    export_govc_env_var

    cp -f build/yamls/*.yml $WORKDIR
    docker save -o antrea-ubuntu.tar projects.registry.vmware.com/antrea/antrea-ubuntu:latest

    echo "===== Deliver Antrea to Linux nodes ====="
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 !~ /win/ {print $6}' | while read IP; do
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar jenkins@${IP}:${WORKDIR}/antrea-ubuntu.tar
        ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker images | grep 'antrea-ubuntu' | awk '{print \$3}' | xargs -r docker rmi ; docker load -i ${WORKDIR}/antrea-ubuntu.tar ; docker images | grep '<none>' | awk '{print \$3}' | xargs -r docker rmi" || true
    done

    echo "===== Deliver Antrea Windows to Windows nodes ====="
    rm -f antrea-windows.tar.gz
    sed -i 's/if (!(Test-Path $AntreaAgentConfigPath))/if ($true)/' hack/windows/Helper.psm1
    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role && $1 ~ /win/ {print $6}' | while read IP; do
        govc snapshot.revert -vm.ip ${IP} win-initial
        harbor_images=("sigwindowstools-kube-proxy:v1.18.0" "e2eteam-agnhost:2.13" "e2eteam-jessie-dnsutils:1.0" "e2eteam-pause:3.2")
        antrea_images=("sigwindowstools/kube-proxy:v1.18.0" "e2eteam/agnhost:2.13" "e2eteam/jessie-dnsutils:1.0" "e2eteam/pause:3.2")
        for i in "${!harbor_images[@]}"; do
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} && docker tag ${DOCKER_REGISTRY}/antrea/${harbor_images[i]} ${antrea_images[i]}" || true
        done

        # Use a script to run antrea agent in windows Network Policy cases
        if [ "$TESTCASE" == "windows-networkpolicy" ]; then
            for i in `seq 24`; do
                sleep 5
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "W32tm /resync /force" | grep successfully && break
            done
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell stop-service kubelet"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell restart-service docker"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell start-service kubelet"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell start-service ovsdb-server"
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "powershell start-service ovs-vswitchd"
            echo "===== Use script to startup antrea agent ====="
            ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -rf /cygdrive/c/k/antrea && mkdir -p /cygdrive/c/k/antrea/bin && mkdir -p /cygdrive/c/k/antrea/etc && rm -rf /cygdrive/c/opt/cni/bin && mkdir -p /cygdrive/c/opt/cni/bin && mkdir -p /cygdrive/c/etc/cni/net.d"
            scp -o StrictHostKeyChecking=no -T $KUBECONFIG Administrator@${IP}:/cygdrive/c/k/config
            scp -o StrictHostKeyChecking=no -T bin/antrea-agent.exe Administrator@${IP}:/cygdrive/c/k/antrea/bin/
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
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/golang:1.15 && docker tag ${DOCKER_REGISTRY}/antrea/golang:1.15 golang:1.15"
                ssh -o StrictHostKeyChecking=no -n Administrator@${IP} "rm -rf antrea && mkdir antrea && cd antrea && tar -xzf ../antrea_repo.tar.gz && sed -i \"s|build/images/Dockerfile.build.windows .|build/images/Dockerfile.build.windows . --network host|g\" Makefile && NO_PULL=${NO_PULL} make build-windows && docker save -o antrea-windows.tar ${DOCKER_REGISTRY}/antrea/antrea-windows:latest && gzip -f antrea-windows.tar" || true
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
    export KUBECONFIG=$KUBECONFIG_PATH
    kubectl delete ns antrea-test || true
    kubectl delete daemonset antrea-agent -n kube-system || true
    kubectl delete -f ${WORKDIR}/antrea.yml || true

    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE="${WORKSPACE}/../gocache"
    export PATH=${GOROOT}/bin:$PATH
    export KUBECONFIG=$KUBECONFIG_PATH

    git show --numstat
    make clean
    docker images | grep 'antrea-ubuntu' | awk '{print $3}' | xargs -r docker rmi -f || true
    docker images | grep '<none>' | awk '{print $3}' | xargs -r docker rmi || true
    if [[ "${DOCKER_REGISTRY}" != "" ]]; then
        docker pull "${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3"
        docker tag "${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3" "sonobuoy/systemd-logs:v0.3"
    fi
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-ubuntu-all.sh --pull
    make flow-aggregator-image

    echo "====== Delivering Antrea to all the Nodes ======"
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

    cp -f build/yamls/*.yml $WORKDIR
    docker save -o antrea-ubuntu.tar projects.registry.vmware.com/antrea/antrea-ubuntu:latest
    docker save -o flow-aggregator.tar projects.registry.vmware.com/antrea/flow-aggregator:latest

    kubectl get nodes -o wide --no-headers=true | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 != role {print $6}' | while read IP; do
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" antrea-ubuntu.tar jenkins@[${IP}]:${WORKDIR}/antrea-ubuntu.tar
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" flow-aggregator.tar jenkins@[${IP}]:${WORKDIR}/flow-aggregator.tar
        ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker images | grep 'antrea-ubuntu' | awk '{print \$3}' | xargs -r docker rmi ; docker load -i ${WORKDIR}/antrea-ubuntu.tar ; docker images | grep '<none>' | awk '{print \$3}' | xargs -r docker rmi" || true
        ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker images | grep 'flow-aggregator' | awk '{print \$3}' | xargs -r docker rmi ; docker load -i ${WORKDIR}/flow-aggregator.tar ; docker images | grep '<none>' | awk '{print \$3}' | xargs -r docker rmi" || true
        if [[ "${DOCKER_REGISTRY}" != "" ]]; then
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "docker pull ${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3 ; docker tag ${DOCKER_REGISTRY}/antrea/sonobuoy-systemd-logs:v0.3 sonobuoy/systemd-logs:v0.3"
        fi
    done
}

function run_e2e {
    echo "====== Running Antrea E2E Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH
    export KUBECONFIG=$KUBECONFIG_PATH

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"
    cp -f "${WORKDIR}/kube.conf" "${WORKDIR}/.kube/config"
    cp -f "${WORKDIR}/ssh-config" "${WORKDIR}/.ssh/config"

    set +e
    mkdir -p `pwd`/antrea-test-logs
    go test -v github.com/vmware-tanzu/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs -timeout=100m --prometheus
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
    export KUBECONFIG=$KUBECONFIG_PATH

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
    export KUBECONFIG=$KUBECONFIG_PATH

    clean_for_windows_install_cni
    wait_for_antrea_windows_pods_ready

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"
    cp -f "${WORKDIR}/kube.conf" "${WORKDIR}/.kube/config"
    cp -f "${WORKDIR}/ssh-config" "${WORKDIR}/.ssh/config"

    set +e
    mkdir -p `pwd`/antrea-test-logs
    go test -v github.com/vmware-tanzu/antrea/test/e2e --logs-export-dir `pwd`/antrea-test-logs --provider remote -timeout=50m --prometheus
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
    export KUBECONFIG=$KUBECONFIG_PATH

    clean_for_windows_install_cni
    if [[ "$TESTCASE" == "windows-conformance" ]]; then
        # Antrea Windows agent Pods are deployed for Windows Conformance test
        wait_for_antrea_windows_pods_ready
    else
        # Antrea Windows agent are deployed with scripts as processes on host for Windows NetworkPolicy test
        wait_for_antrea_windows_processes_ready
    fi

    echo "====== Run test with e2e.test ======"
    export KUBE_TEST_REPO_LIST=${WORKDIR}/repo_list
    if [ "$TESTCASE" == "windows-networkpolicy" ]; then
        ginkgo -p -nodes 8 --seed=1592804472 --noColor $E2ETEST_PATH -- --provider=skeleton --ginkgo.focus="$WINDOWS_NETWORKPOLICY_FOCUS" --ginkgo.skip="$WINDOWS_NETWORKPOLICY_SKIP" > windows_conformance_result_no_color.txt || true
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

    IP=$(govc vm.ip $OVS_VM_NAME)
    govc snapshot.revert -vm $OVS_VM_NAME initial
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

if [[ ${TESTCASE} == "windows-install-ovs" ]]; then
    run_install_windows_ovs
elif [[ ${TESTCASE} =~ "windows" ]]; then
    deliver_antrea_windows
    if [[ ${TESTCASE} =~ "e2e" ]]; then
        run_e2e_windows
    else
        run_conformance_windows
    fi
    clean_antrea
elif [[ ${TESTCASE} =~ "e2e" ]]; then
    deliver_antrea
    run_e2e
    clean_antrea
else
    deliver_antrea
    run_conformance
    clean_antrea
fi

if [[ ${TEST_FAILURE} == true ]]; then
    exit 1
fi
