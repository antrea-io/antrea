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

GKE_ZONE="us-west1-a"
GKE_HOST="UBUNTU"
MACHINE_TYPE="e2-standard-4"
GKE_SERVICE_CIDR="10.94.0.0/16"
GKE_PROJECT="antrea"
KUBECONFIG_PATH="$HOME/jenkins/out/gke"
MODE="report"
RUN_ALL=true
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
TEST_FAILURE=false
KUBE_CONFORMANCE_IMAGE_VERSION=v1.18.5

_usage="Usage: $0 [--cluster-name <GKEClusterNameToUse>]  [--kubeconfig <KubeconfigSavePath>] [--k8s-version <ClusterVersion>] \
                  [--svc-account <Name>] [--user <Name>] [--gke-project <Project>] [--gke-zone <Zone>] [--log-mode <SonobuoyResultLogLevel>] \
                  [--svc-cidr <ServiceCIDR>] [--host-type <HostType] [--machine-type <MachineType] [--gloud-path] [--setup-only] [--cleanup-only]

Setup a GKE cluster to run K8s e2e community tests (Conformance & Network Policy).
Before running the script, login to gcloud with \`gcloud auth login\` or \`gcloud auth activate-service-account\`
and create the project to be used for cluster with \`gcloud projects create\`.

        --cluster-name        The cluster name to be used for the generated GKE cluster. Must be specified if not run in Jenkins environment.
        --kubeconfig          Path to save kubeconfig of generated GKE cluster.
        --k8s-version         GKE K8s cluster version. Defaults to the latest supported master version documented at https://cloud.google.com/kubernetes-engine/docs/release-notes.
        --svc-account         Service acount name if logged in with service account. Use --user instead if logged in with gcloud auth login.
        --user                Email address if logged in with user account. Use --svc-account instead if logged in with service account.
        --gke-project         The GKE project to be used. Needs to be pre-created before running the script.
        --gke-zone            The GKE zone where the cluster will be initiated. Defaults to us-west1-a.
        --svc-cidr            The service CIDR to be used for cluster. Defaults to 10.94.0.0/16.
        --host-type           The host type of worker node. Defaults to UBUNTU.
        --machine-type        The machine type of worker node. Defaults to e2-standard-4.
        --gcloud-path         The path of gcloud installation. Only need to be explicitly set for Jenkins environments.
        --log-mode            Use the flag to set either 'report', 'detail', or 'dump' level data for sonobouy results.
        --setup-only          Only perform setting up the cluster and run test.
        --cleanup-only        Only perform cleaning up the cluster."


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
    --kubeconfig)
    KUBECONFIG_PATH="$2"
    shift 2
    ;;
    --gke-project)
    GKE_PROJECT="$2"
    shift 2
    ;;
    --svc-account)
    SVC_ACCOUNT_NAME="$2"
    shift 2
    ;;
    --user)
    USER_EMAIL="$2"
    shift 2
    ;;
    --gke-zone)
    GKE_ZONE="$2"
    shift 2
    ;;
    --svc-cidr)
    GKE_SERVICE_CIDR="$2"
    shift 2
    ;;
    --host-type)
    GKE_HOST="$2"
    shift 2
    ;;
    --machine-type)
    MACHINE_TYPE="$2"
    shift 2
    ;;
    --k8s-version)
    K8S_VERSION="$2"
    shift 2
    ;;
    --gcloud-path)
    GCLOUD_PATH="$2"
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

if [[ -z ${GCLOUD_PATH+x} ]]; then
    GCLOUD_PATH=$(which gcloud)
fi

function setup_gke() {

    if [[ -z ${K8S_VERSION+x} ]]; then
        K8S_VERSION=$(${GCLOUD_PATH} container get-server-config --zone ${GKE_ZONE} | awk '/validMasterVersions/{getline;print}' | cut -c3- )
    fi

    echo "=== This cluster to be created is named: ${CLUSTER} ==="
    echo "CLUSTERNAME=${CLUSTER}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
    if [[ -n ${ANTREA_GIT_REVISION+x} ]]; then
        echo "ANTREA_REPO=${ANTREA_REPO}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
        echo "ANTREA_GIT_REVISION=${ANTREA_GIT_REVISION}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
    fi

    echo "=== Using the following gcloud version ==="
    ${GCLOUD_PATH} --version
    echo "=== Using the following kubectl ==="
    which kubectl

    echo '=== Creating a cluster in GKE ==='
    ${GCLOUD_PATH} container --project ${GKE_PROJECT} clusters create ${CLUSTER} \
        --image-type ${GKE_HOST} --machine-type ${MACHINE_TYPE} \
        --cluster-version ${K8S_VERSION} --zone ${GKE_ZONE} \
        --enable-ip-alias --services-ipv4-cidr ${GKE_SERVICE_CIDR}
    if [[ $? -ne 0 ]]; then
        echo "=== Failed to deploy GKE cluster! ==="
        exit 1
    fi

    mkdir -p ${KUBECONFIG_PATH}
    ${GCLOUD_PATH} container clusters get-credentials ${CLUSTER} --zone ${GKE_ZONE} > ${KUBECONFIG_PATH}/kubeconfig

    sleep 10
    if [[ $(kubectl get nodes) ]]; then
        echo "=== GKE cluster setup succeeded ==="
    else
        echo "=== GKE cluster is not configured correctly! ==="
        exit 1
    fi
}

function deliver_antrea_to_gke() {
    echo "====== Building Antrea for the Following Commit ======"
    git show --numstat

    export GO111MODULE=on
    export GOROOT=/usr/local/go
    export PATH=${GOROOT}/bin:$PATH

    if [[ -z ${GIT_CHECKOUT_DIR+x} ]]; then
        GIT_CHECKOUT_DIR=..
    fi
    make clean -C ${GIT_CHECKOUT_DIR}
    if [[ -n ${JOB_NAME+x} ]]; then
        docker images | grep "${JOB_NAME}" | awk '{print $3}' | xargs -r docker rmi -f || true > /dev/null
    fi
    # Clean up dangling images generated in previous builds. Recent ones must be excluded
    # because they might be being used in other builds running simultaneously.
    docker image prune -f --filter "until=2h" || true > /dev/null

    cd ${GIT_CHECKOUT_DIR}
    VERSION="$CLUSTER" make
    if [[ "$?" -ne "0" ]]; then
        echo "=== Antrea Image build failed ==="
        exit 1
    fi

    echo "=== Loading the Antrea image to each Node ==="
    antrea_image="antrea-ubuntu"
    DOCKER_IMG_VERSION=${CLUSTER}
    docker save -o ${antrea_image}.tar antrea/antrea-ubuntu:${DOCKER_IMG_VERSION}

    node_names=$(kubectl get nodes -o wide --no-headers=true | awk '{print $1}')
    for node_name in ${node_names}; do
        ${GCLOUD_PATH} compute scp ${antrea_image}.tar ubuntu@${node_name}:~ --zone ${GKE_ZONE}
        ${GCLOUD_PATH} compute ssh ubuntu@${node_name} --command="sudo docker load -i ~/${antrea_image}.tar ; sudo docker tag antrea/antrea-ubuntu:${DOCKER_IMG_VERSION} antrea/antrea-ubuntu:latest" --zone ${GKE_ZONE}
    done
    rm ${antrea_image}.tar

    echo "=== Configuring Antrea for cluster ==="
    if [[ -n ${SVC_ACCOUNT_NAME+x} ]]; then
        ${GCLOUD_PATH} projects add-iam-policy-binding ${GKE_PROJECT} --member serviceAccount:${SVC_ACCOUNT_NAME} --role roles/container.admin
        kubectl create clusterrolebinding cluster-admin-binding --clusterrole cluster-admin --user ${SVC_ACCOUNT_NAME}
    elif [[ -n ${USER_EMAIL+x} ]]; then
        ${GCLOUD_PATH} projects add-iam-policy-binding ${GKE_PROJECT} --member user:${USER_EMAIL} --role roles/container.admin
        kubectl create clusterrolebinding cluster-admin-binding --clusterrole cluster-admin --user ${USER_EMAIL}
    else
        echo "Neither service account or user email info is set, cannot create cluster-admin-binding!"
        echo "Please refer to --help for more information."
        exit 1
    fi

    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke-node-init.yml
    sed -i "s|#defaultMTU: 1450|defaultMTU: 1500|g" ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke.yml
    sed -i "s|#serviceCIDR: 10.96.0.0/12|serviceCIDR: ${GKE_SERVICE_CIDR}|g" ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke.yml
    echo "defaultMTU set as 1450"
    echo "seviceCIDR set as ${GKE_SERVICE_CIDR}"

    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke.yml
    kubectl rollout status --timeout=2m deployment.apps/antrea-controller -n kube-system
    kubectl rollout status --timeout=2m daemonset/antrea-agent -n kube-system

    # Restart all Pods in all Namespaces (kube-system, etc) so they can be managed by Antrea.
    kubectl delete pods -n kube-system $(kubectl get pods -n kube-system -o custom-columns=NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork \
        --no-headers=true | grep '<none>' | awk '{ print $1 }')
    kubectl rollout status --timeout=2m deployment.apps/kube-dns -n kube-system
    # wait for other pods in the kube-system namespace to become ready
    sleep 5

    echo "=== Antrea has been deployed for GKE cluster ${CLUSTER} ==="
}

function run_conformance() {
    echo "=== Running Antrea Conformance and Network Policy Tests ==="

    # Allow nodeport traffic by external IP
    ${GCLOUD_PATH} compute firewall-rules create allow-nodeport --allow tcp:30000-32767

    ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-conformance --e2e-network-policy \
      --kube-conformance-image-version ${KUBE_CONFORMANCE_IMAGE_VERSION} \
      --log-mode ${MODE} > ${GIT_CHECKOUT_DIR}/gke-test.log

    ${GCLOUD_PATH} compute firewall-rules delete allow-nodeport
    if grep -Fxq "Failed tests:" ${GIT_CHECKOUT_DIR}/gke-test.log
    then
        echo "Failed cases exist."
        TEST_FAILURE=true
    else
        echo "All tests passed."
    fi

    if [[ -z ${GIT_CHECKOUT_DIR+x} ]]; then
        GIT_CHECKOUT_DIR=..
    fi
    echo "=== Cleanup Antrea Installation ==="
    for antrea_yml in ${GIT_CHECKOUT_DIR}/build/yamls/*.yml
    do
        kubectl delete -f ${antrea_yml} --ignore-not-found=true || true
    done

    if [[ "$TEST_FAILURE" == false ]]; then
        echo "=== SUCCESS !!! ==="
    fi
    echo "=== FAILURE !!! ==="
}

function cleanup_cluster() {
    echo '=== Cleaning up GKE cluster ${cluster} ==='
    retry=5
    while [[ "${retry}" -gt 0 ]]; do
       yes | ${GCLOUD_PATH} container clusters delete ${CLUSTER} --zone ${GKE_ZONE}
       if [[ $? -eq 0 ]]; then
         break
       fi
       sleep 10
       retry=$((retry-1))
    done
    if [[ "${retry}" -eq 0 ]]; then
       echo "=== Failed to delete GKE cluster ${CLUSTER}! ==="
       exit 1
    fi
    rm -f ${KUBECONFIG_PATH}/kubeconfig
    echo "=== Cleanup cluster ${CLUSTER} succeeded ==="
}

# ensures that the script can be run from anywhere
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
GIT_CHECKOUT_DIR=${THIS_DIR}/..
pushd "$THIS_DIR" > /dev/null

if [[ "$RUN_ALL" == true || "$RUN_SETUP_ONLY" == true ]]; then
    setup_gke
    deliver_antrea_to_gke
    run_conformance
fi

if [[ "$RUN_ALL" == true || "$RUN_CLEANUP_ONLY" == true ]]; then
    cleanup_cluster
fi

if [[ "$RUN_CLEANUP_ONLY" == false &&  "$TEST_FAILURE" == true ]]; then
    exit 1
fi
