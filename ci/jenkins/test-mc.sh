#!/usr/bin/env bash

# Copyright 2021 Antrea Authors
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
TESTCASE=""
TEST_FAILURE=false
DOCKER_REGISTRY=$(head -n1 "${WORKSPACE}/ci/docker-registry")
GO_VERSION=$(head -n1 "${WORKSPACE}/build/images/deps/go-version")
IMAGE_PULL_POLICY="Always"
MULTICLUSTER_KUBECONFIG_PATH=$WORKDIR/.kube
LEADER_CLUSTER_CONFIG="--kubeconfig=$MULTICLUSTER_KUBECONFIG_PATH/leader"
EAST_CLUSTER_CONFIG="--kubeconfig=$MULTICLUSTER_KUBECONFIG_PATH/east"
WEST_CLUSTER_CONFIG="--kubeconfig=$MULTICLUSTER_KUBECONFIG_PATH/west"

NGINX_IMAGE=projects.registry.vmware.com/antrea/nginx:1.21.6-alpine

CONTROL_PLANE_NODE_ROLE="control-plane,master"

multicluster_kubeconfigs=($EAST_CLUSTER_CONFIG $LEADER_CLUSTER_CONFIG $WEST_CLUSTER_CONFIG)
membercluter_kubeconfigs=($EAST_CLUSTER_CONFIG $WEST_CLUSTER_CONFIG)


CLEAN_STALE_IMAGES="docker system prune --force --all --filter until=48h"

_usage="Usage: $0 [--kubeconfigs-path <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--testcase <e2e>]

Run Antrea multi-cluster e2e tests on a remote (Jenkins) Linux Cluster Set.

        --kubeconfigs-path            Path of cluster set kubeconfigs.
        --workdir                     Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase                    Antrea multi-cluster e2e test cases on a Linux cluster set.
        --registry                    The docker registry to use instead of dockerhub."

function print_usage {
    echoerr "$_usage"
}


while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --kubeconfigs-path)
    MULTICLUSTER_KUBECONFIG_PATH="$2"
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


function cleanup_multicluster_ns {
    ns=$1
    kubeconfig=$2

    kubectl delete ns "${ns}" --ignore-not-found=true ${kubeconfig} --timeout=30s || true
}

function cleanup_multicluster_controller {
    echo "====== Cleanup Multicluster Controller Installation ======"
    kubeconfig=$1
    for multicluster_yml in ${WORKSPACE}/multicluster/test/yamls/*.yml; do
        kubectl delete -f $multicluster_yml $kubeconfig --ignore-not-found=true  --timeout=30s || true
    done

    for multicluster_yml in ${WORKSPACE}/multicluster/build/yamls/*.yml; do
        kubectl delete -f $multicluster_yml $kubeconfig --ignore-not-found=true --timeout=30s || true
    done
}

function cleanup_multicluster_antrea {
    echo "====== Cleanup Antrea controller and agent ======"
    kubeconfig=$1
    kubectl get pod -n kube-system -l component=antrea-agent --no-headers=true $kubeconfig | awk '{print $1}' | while read AGENTNAME; do
       kubectl exec $AGENTNAME -c antrea-agent -n kube-system ${kubeconfig}  ovs-vsctl del-port br-int gw0 || true
    done

   for antrea_yml in ${WORKDIR}/*.yml; do
        kubectl delete -f $antrea_yml --ignore-not-found=true ${kubeconfig} --timeout=30s || true
    done
}

function clean_multicluster {
    echo "====== Cleanup Multicluster Antrea Installation in clusters ======"
    for kubeconfig in ${multicluster_kubeconfigs[@]}
    do
        cleanup_multicluster_ns "antrea-multicluster-test" $kubeconfig
        cleanup_multicluster_ns "antrea-mcs-ns" $kubeconfig
        cleanup_multicluster_controller $kubeconfig
        cleanup_multicluster_antrea $kubeconfig
    done
}

function wait_for_antrea_multicluster_pods_ready {
    kubeconfig=$1
    kubectl apply -f build/yamls/antrea.yml "${kubeconfig}"
    kubectl rollout restart deployment/coredns -n kube-system "${kubeconfig}"
    kubectl rollout status deployment/coredns -n kube-system "${kubeconfig}"
    kubectl rollout status deployment.apps/antrea-controller -n kube-system "${kubeconfig}"
    kubectl rollout status daemonset/antrea-agent -n kube-system "${kubeconfig}"
}

function wait_for_multicluster_controller_ready {
    kubectl create ns antrea-mcs-ns  "${LEADER_CLUSTER_CONFIG}" || true
    kubectl apply -f ./multicluster/test/yamls/manifest.yml "${LEADER_CLUSTER_CONFIG}"
    kubectl apply -f ./multicluster/build/yamls/antrea-multicluster-leader-global.yml "${LEADER_CLUSTER_CONFIG}"
    kubectl rollout status deployment/antrea-mc-controller -n antrea-mcs-ns "${LEADER_CLUSTER_CONFIG}" || true
    kubectl apply -f ./multicluster/test/yamls/manifest.yml "${LEADER_CLUSTER_CONFIG}"
    kubectl create -f ./multicluster/test/yamls/leader-access-token-secret.yml "${LEADER_CLUSTER_CONFIG}" || true
    kubectl get secret -n antrea-mcs-ns leader-access-token "${LEADER_CLUSTER_CONFIG}" -o yaml > ./multicluster/test/yamls/leader-access-token.yml

    sed -i '/uid:/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/resourceVersion/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/last-applied-configuration/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/type/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/creationTimestamp/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i 's/antrea-multicluster-member-access-sa/antrea-multicluster-controller/g' ./multicluster/test/yamls/leader-access-token.yml
    sed -i 's/antrea-mcs-ns/kube-system/g' ./multicluster/test/yamls/leader-access-token.yml
    echo "type: Opaque" >>./multicluster/test/yamls/leader-access-token.yml

    for config in ${membercluter_kubeconfigs[@]};
    do
        kubectl apply -f ./multicluster/build/yamls/antrea-multicluster-member.yml ${config}
        kubectl rollout status deployment/antrea-mc-controller -n kube-system ${config}
        kubectl apply -f ./multicluster/test/yamls/leader-access-token.yml ${config}
    done

    kubectl apply -f ./multicluster/test/yamls/east-member-cluster.yml "${EAST_CLUSTER_CONFIG}"
    kubectl apply -f ./multicluster/test/yamls/west-member-cluster.yml "${WEST_CLUSTER_CONFIG}"
    kubectl apply -f ./multicluster/test/yamls/clusterset.yml "${LEADER_CLUSTER_CONFIG}"
}

function deliver_antrea_multicluster {
    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export PATH=${GOROOT}/bin:$PATH

    git show --numstat
    make clean
    ${CLEAN_STALE_IMAGES}

    cp -f build/yamls/*.yml $WORKDIR
    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull
    echo "====== Delivering Antrea to all the Nodes ======"
    docker save -o ${WORKDIR}/antrea-ubuntu.tar $DOCKER_REGISTRY/antrea/antrea-ubuntu:latest


    for kubeconfig in ${multicluster_kubeconfigs[@]}
    do
       kubectl get nodes -o wide --no-headers=true ${kubeconfig}| awk '{print $6}' | while read IP; do
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/antrea-ubuntu.tar jenkins@[${IP}]:${WORKDIR}/antrea-ubuntu.tar
            ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES}; docker load -i ${WORKDIR}/antrea-ubuntu.tar" || true
       done
    done
}

function deliver_multicluster_controller {
    echo "====== Build Antrea Multiple Cluster Controller and YAMLs ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export PATH=${GOROOT}/bin:$PATH

    docker images | grep 'mc-controller' | awk '{print $3}' | xargs -r docker rmi || true
    export NO_PULL=1;make antrea-mc-controller

    docker save antrea/antrea-mc-controller:latest -o "${WORKDIR}"/antrea-mcs.tar
    ./multicluster/hack/generate-manifest.sh -l antrea-mcs-ns >./multicluster/test/yamls/manifest.yml

    for kubeconfig in ${multicluster_kubeconfigs[@]}
    do
        kubectl get nodes -o wide --no-headers=true "${kubeconfig}"| awk '{print $6}' | while read IP; do
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/antrea-mcs.tar jenkins@[${IP}]:${WORKDIR}/antrea-mcs.tar
            ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "${CLEAN_STALE_IMAGES}; docker load -i ${WORKDIR}/antrea-mcs.tar" || true
        done
    done

    leader_ip=$(kubectl get nodes -o wide --no-headers=true ${LEADER_CLUSTER_CONFIG} | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 == role {print $6}')
    sed -i "s|<LEADER_CLUSTER_IP>|${leader_ip}|" ./multicluster/test/yamls/east-member-cluster.yml
    sed -i "s|<LEADER_CLUSTER_IP>|${leader_ip}|" ./multicluster/test/yamls/west-member-cluster.yml

    for kubeconfig in ${membercluter_kubeconfigs[@]}
    do
       ip=$(kubectl get nodes -o wide --no-headers=true ${EAST_CLUSTER_CONFIG} | awk -v role="$CONTROL_PLANE_NODE_ROLE" '$3 == role {print $6}')
       rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" ./multicluster/test/yamls/test-east-serviceexport.yml jenkins@[${ip}]:${WORKDIR}/serviceexport.yml
    done
}

function run_multicluster_e2e {
   echo "====== Running Multicluster e2e Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    wait_for_antrea_multicluster_pods_ready "${LEADER_CLUSTER_CONFIG}"
    wait_for_antrea_multicluster_pods_ready "${EAST_CLUSTER_CONFIG}"
    wait_for_antrea_multicluster_pods_ready "${WEST_CLUSTER_CONFIG}"

    wait_for_multicluster_controller_ready

    docker pull $NGINX_IMAGE
    docker save $NGINX_IMAGE -o "${WORKDIR}"/nginx.tar

    docker pull "${DOCKER_REGISTRY}/antrea/agnhost:2.26"
    docker tag "${DOCKER_REGISTRY}/antrea/agnhost:2.26" "agnhost:2.26"
    docker save agnhost:2.26 -o "${WORKDIR}"/agnhost.tar

    for kubeconfig in ${membercluter_kubeconfigs[@]}
    do
        kubectl get nodes -o wide --no-headers=true "${kubeconfig}"| awk '{print $6}' | while read IP; do
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/nginx.tar jenkins@["${IP}"]:"${WORKDIR}"/nginx.tar
            ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "${CLEAN_STALE_IMAGES}; docker load -i ${WORKDIR}/nginx.tar" || true

            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/agnhost.tar jenkins@["${IP}"]:"${WORKDIR}"/agnhost.tar
            ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "docker load -i ${WORKDIR}/agnhost.tar" || true
        done

    done

    set +e
    mkdir -p `pwd`/antrea-multicluster-test-logs
    go test -v antrea.io/antrea/multicluster/test/e2e --logs-export-dir  `pwd`/antrea-multicluster-test-logs
    if [[ "$?" != "0" ]]; then
        TEST_FAILURE=true
    fi
    set -e
}

trap clean_multicluster EXIT
clean_tmp

if [[ ${TESTCASE} =~ "e2e" ]]; then
    deliver_antrea_multicluster
    deliver_multicluster_controller
    run_multicluster_e2e
fi

if [[ ${TEST_FAILURE} == true ]]; then
    exit 1
fi
