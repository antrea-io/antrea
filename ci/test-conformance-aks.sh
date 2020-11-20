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

set -exu

function echoerr {
    >&2 echo "$@"
}

REGION="westus"
RESOURCE_GROUP="antrea-ci-rg"
RUN_ALL=true
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
KUBECONFIG_PATH="$HOME/jenkins/out/aks"
TEST_FAILURE=false
MODE="report"
KUBE_CONFORMANCE_IMAGE_VERSION=v1.18.5

_usage="Usage: $0 [--cluster-name <AKSClusterNameToUse>] [--kubeconfig <KubeconfigSavePath>] [--k8s-version <ClusterVersion>]\
                  [--azure-app-id <AppID>] [--azure-tenant-id <TenantID>] [--azure-password <Password>] \
                  [--aks-region <Region>] [--log-mode <SonobuoyResultLogLevel>] [--setup-only] [--cleanup-only]

Setup a AKS cluster to run K8s e2e community tests (Conformance & Network Policy).

        --cluster-name           The cluster name to be used for the generated AKS cluster. Must be specified if not run in Jenkins environment.
        --kubeconfig             Path to save kubeconfig of generated AKS cluster.
        --k8s-version            AKS K8s cluster version. Defaults to first supported version in the Azure region.
        --azure-app-id           Azure Service Principal Application ID.
        --azure-tenant-id        Azure Service Principal Tenant ID.
        --azure-password         Azure Service Principal Password.
        --aks-region             The Azure region where the cluster will be initiated. Defaults to westus.
        --log-mode               Use the flag to set either 'report', 'detail', or 'dump' level data for sonobouy results.
        --setup-only             Only perform setting up the cluster and run test.
        --cleanup-only           Only perform cleaning up the cluster."

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
    CLUSTER="$2"
    shift 2
    ;;
    --azure-app-id)
    AZURE_APP_ID="$2"
    shift 2
    ;;
    --azure-tenant-id)
    AZURE_TENANT_ID="$2"
    shift 2
    ;;
     --azure-password)
    AZURE_PASSWORD="$2"
    shift 2
    ;;
    --aks-region)
    REGION="$2"
    shift 2
    ;;
    --kubeconfig)
    KUBECONFIG_PATH="$2"
    shift 2
    ;;
    --k8s-version)
    K8S_VERSION="$2"
    shift 2
    ;;
    --log-mode)
    MODE="$2"
    shift 2
    ;;
    --setup-only)
    RUN_SETUP_ONLY=true
    RUN_ALL=false
    shift
    ;;
    --cleanup-only)
    RUN_CLEANUP_ONLY=true
    RUN_ALL=false
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

function setup_aks() {
    echo "=== This cluster to be created is named: ${CLUSTER} in resource group ${RESOURCE_GROUP} ==="

    # Save the cluster information for cleanup on Jenkins environment
    echo "CLUSTERNAME=${CLUSTER}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt

    echo "=== Using the following az cli version ==="
    az --version

    echo "=== Logging into Azure Cloud ==="
    az login --service-principal --username ${AZURE_APP_ID} --password ${AZURE_PASSWORD} --tenant ${AZURE_TENANT_ID}

    printf "\n"
    echo "=== Using the following kubectl ==="
    which kubectl

    echo '=== Creating a resource group ==='
    az group create --name ${RESOURCE_GROUP} --location $REGION

    if [[ -z ${K8S_VERSION+x} ]]; then
        K8S_VERSION=$(az aks get-versions -l ${REGION} | grep "orchestratorVersion" | head -n1 | cut -d'"' -f4)
    fi

    echo '=== Creating a cluster in AKS ==='
    az aks create \
        --resource-group ${RESOURCE_GROUP} \
        --name ${CLUSTER} \
        --node-count 2 \
        --network-plugin azure \
        --kubernetes-version ${K8S_VERSION} \
        --service-principal ${AZURE_APP_ID} \
        --client-secret ${AZURE_PASSWORD}
    if [[ $? -ne 0 ]]; then
        echo "=== Failed to deploy AKS cluster! ==="
        exit 1
    fi

    mkdir -p ${KUBECONFIG_PATH}
    az aks get-credentials --resource-group ${RESOURCE_GROUP} \
        --name ${CLUSTER} --file ${KUBECONFIG_PATH}/kubeconfig
    export KUBECONFIG="${KUBECONFIG_PATH}/kubeconfig"

    sleep 5
    if [[ $(kubectl get svc) ]]; then
        echo "=== AKS cluster setup succeeded ==="
    else
        echo "=== AKS kubectl is not configured correctly! ==="
        exit 1
    fi
}

function deliver_antrea_to_aks() {
    echo "=== Configuring Antrea for AKS cluster ==="

    if [[ -z ${GIT_CHECKOUT_DIR+x} ]]; then
        GIT_CHECKOUT_DIR=..
    fi
    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-aks-node-init.yml
    sleep 5s

    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-aks.yml
    kubectl rollout status --timeout=2m deployment.apps/antrea-controller -n kube-system
    kubectl rollout status --timeout=2m daemonset/antrea-agent -n kube-system

  # Restart all Pods in all Namespaces (kube-system, etc) so they can be managed by Antrea.
    kubectl delete pods -n kube-system $(kubectl get pods -n kube-system -o custom-columns=NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork \
                        --no-headers=true | grep '<none>' | awk '{ print $1 }')
    kubectl rollout status --timeout=2m deployment.apps/coredns -n kube-system
    # wait for other pods in the kube-system namespace to become ready
    sleep 5

    echo "=== Antrea has been deployed for AKS cluster ${CLUSTER} ==="
}

function run_conformance() {
    echo "=== Running Antrea Conformance and Network Policy Tests ==="
    ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-conformance --e2e-network-policy \
      --kube-conformance-image-version ${KUBE_CONFORMANCE_IMAGE_VERSION} \
      --log-mode ${MODE} > ${GIT_CHECKOUT_DIR}/aks-test.log

    if grep -Fxq "Failed tests:" ${GIT_CHECKOUT_DIR}/aks-test.log
    then
        echo "Failed cases exist."
        echo "=== FAILURE !!! ==="
    else
        echo "All tests passed."
        echo "=== SUCCESS !!! ==="
    fi
}

function cleanup_cluster() {
    echo '=== Cleaning up AKS cluster ${CLUSTER} ==='
    az aks delete --name  ${CLUSTER} --resource-group ${RESOURCE_GROUP} --yes
    if [[ $? -ne 0 ]]; then
        echo "== Failed to delete AKS cluster"
        exit
    fi

    az group delete --name ${RESOURCE_GROUP} --yes --no-wait
    if [[ $? -ne 0 ]]; then
        echo "== Failed to delete AKS resource group"
        exit
    fi

    rm -f ${KUBECONFIG_PATH}/kubeconfig
    echo "=== Cleanup cluster ${CLUSTER} succeeded ==="
}

# ensures that the script can be run from anywhere
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
GIT_CHECKOUT_DIR=${THIS_DIR}/..
pushd "$THIS_DIR" > /dev/null

if [[ "$RUN_ALL" == true || "$RUN_SETUP_ONLY" == true ]]; then
    setup_aks
    deliver_antrea_to_aks
    run_conformance
fi

if [[ "$RUN_ALL" == true || "$RUN_CLEANUP_ONLY" == true ]]; then
    cleanup_cluster
fi

if [[ "$RUN_CLEANUP_ONLY" == false &&  "$TEST_FAILURE" == true ]]; then
    exit 1
fi
