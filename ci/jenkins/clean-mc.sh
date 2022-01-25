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

DEFAULT_WORKDIR="/var/lib/jenkins"
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/kube.conf
WORKDIR=$DEFAULT_WORKDIR
TESTCASE=""
TEST_FAILURE=false
DOCKER_REGISTRY=$(head -n1 "/var/lib/jenkins/antrea/ci/docker-registry")
GO_VERSION=$(head -n1 "/var/lib/jenkins/antrea/build/images/deps/go-version")
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
    for multicluster_yml in /var/lib/jenkins/antrea/multicluster/test/yamls/*.yml; do
        kubectl delete -f $multicluster_yml $kubeconfig --ignore-not-found=true  --timeout=30s || true
    done

    for multicluster_yml in /var/lib/jenkins/antrea/multicluster/build/yamls/*.yml; do
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
    for kubeconfig in "${multicluster_kubeconfigs[@]}"
    do
        cleanup_multicluster_ns "antrea-multicluster-test" $kubeconfig
        cleanup_multicluster_ns "antrea-mcs-ns" $kubeconfig
        cleanup_multicluster_controller $kubeconfig
        cleanup_multicluster_antrea $kubeconfig
    done
}

trap clean_multicluster EXIT
clean_tmp

