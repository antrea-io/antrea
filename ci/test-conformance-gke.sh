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
GKE_HOST="UBUNTU_CONTAINERD"
MACHINE_TYPE="e2-standard-4"
GKE_PROJECT="antrea"
KUBECONFIG_PATH="$HOME/jenkins/out/gke"
MODE="report"
RUN_ALL=true
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
SKIP_IAM_POLICY_BINDING=false
TEST_SCRIPT_RC=0
KUBE_CONFORMANCE_IMAGE_VERSION=auto

_usage="Usage: $0 [--cluster-name <GKEClusterNameToUse>]  [--kubeconfig <KubeconfigSavePath>] [--k8s-version <ClusterVersion>] \
                  [--svc-account <Name>] [--user <Name>] [--gke-project <Project>] [--gke-zone <Zone>] [--log-mode <SonobuoyResultLogLevel>] \
                  [--svc-cidr <ServiceCIDR>] [--host-type <HostType] [--machine-type <MachineType] [--gloud-path] [--setup-only] [--cleanup-only]

Setup a GKE cluster to run K8s e2e community tests (Conformance & Network Policy).
Before running the script, login to gcloud with \`gcloud auth login\` or \`gcloud auth activate-service-account\`
and create the project to be used for cluster with \`gcloud projects create\`.

        --cluster-name        The cluster name to be used for the generated GKE cluster. Must be specified if not run in Jenkins environment.
        --kubeconfig          Path to save kubeconfig of generated GKE cluster.
        --k8s-version         GKE K8s cluster version. Defaults to the latest supported stable version documented at https://cloud.google.com/kubernetes-engine/docs/release-notes.
        --svc-account         Service acount name if logged in with service account. Use --user instead if logged in with gcloud auth login.
        --user                Email address if logged in with user account. Use --svc-account instead if logged in with service account.
        --gke-project         The GKE project to be used. Needs to be pre-created before running the script.
        --gke-zone            The GKE zone where the cluster will be initiated. Defaults to us-west1-a.
        --svc-cidr            The service CIDR to be used for cluster. Defaults to 10.94.0.0/16.
        --host-type           The host type of worker node. Defaults to UBUNTU.
        --machine-type        The machine type of worker node. Defaults to e2-standard-4.
        --gcloud-sdk-path     The path of gcloud installation. Only need to be explicitly set for Jenkins environments.
        --log-mode            Use the flag to set either 'report', 'detail', or 'dump' level data for sonobuoy results.
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
    --skip-iam-policy-binding)
    SKIP_IAM_POLICY_BINDING=true
    shift
    ;;
    --gke-zone)
    GKE_ZONE="$2"
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
    --gcloud-sdk-path)
    GCLOUD_SDK_PATH="$2"
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

if [[ ! -z ${GCLOUD_SDK_PATH+x} ]]; then
    export PATH=${GCLOUD_SDK_PATH}/bin:$PATH
fi

if ! [ -x "$(command -v gcloud)" ]; then
    echoerr "gcloud is not available in the PATH; consider using --gcloud-sdk-path"
    exit 1
fi

# ensures that the script can be run from anywhere
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
GIT_CHECKOUT_DIR=${THIS_DIR}/..
pushd "$THIS_DIR" > /dev/null

source ${THIS_DIR}/jenkins/utils.sh

# disable gcloud prompts, e.g., when deleting resources
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

export CLOUDSDK_CORE_PROJECT="$GKE_PROJECT"

function setup_gke() {
    if [[ -z ${K8S_VERSION+x} ]]; then
        K8S_VERSION=$(gcloud container get-server-config --zone ${GKE_ZONE} | awk '/validMasterVersions/{getline;print}' | cut -c3- )
    fi

    echo "=== This cluster to be created is named: ${CLUSTER} ==="
    echo "CLUSTERNAME=${CLUSTER}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
    if [[ -n ${ANTREA_GIT_REVISION+x} ]]; then
        echo "ANTREA_REPO=${ANTREA_REPO}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
        echo "ANTREA_GIT_REVISION=${ANTREA_GIT_REVISION}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
    fi

    echo "=== Using the following gcloud version ==="
    gcloud --version
    echo "=== Using the following kubectl ==="
    which kubectl

    echo '=== Creating a cluster in GKE ==='
    gcloud container clusters create ${CLUSTER} \
        --image-type ${GKE_HOST} --machine-type ${MACHINE_TYPE} \
        --cluster-version ${K8S_VERSION} --zone ${GKE_ZONE} \
        --enable-ip-alias \
        --no-enable-autoupgrade
    if [[ $? -ne 0 ]]; then
        echo "=== Failed to deploy GKE cluster! ==="
        exit 1
    fi

    mkdir -p ${KUBECONFIG_PATH}
    KUBECONFIG=${KUBECONFIG_PATH}/kubeconfig gcloud container clusters get-credentials ${CLUSTER} --zone ${GKE_ZONE}

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

    make clean -C ${GIT_CHECKOUT_DIR}
    # The cleanup and stats are best-effort.
    set +e
    if [[ -n ${JOB_NAME+x} ]]; then
        docker images --format "{{.Repository}}:{{.Tag}}" | grep "${JOB_NAME}" | xargs -r docker rmi -f > /dev/null
    fi
    # Clean up dangling images generated in previous builds. Recent ones must be excluded
    # because they might be being used in other builds running simultaneously.
    docker image prune -f --filter "until=2h" > /dev/null
    docker system df -v
    check_and_cleanup_docker_build_cache
    set -e

    cd ${GIT_CHECKOUT_DIR}
    VERSION="$CLUSTER" ./hack/build-antrea-linux-all.sh --pull
    if [[ "$?" -ne "0" ]]; then
        echo "=== Antrea Image build failed ==="
        exit 1
    fi

    echo "=== Loading the Antrea image to each Node ==="
    antrea_images_tar="antrea-ubuntu.tar"
    DOCKER_IMG_VERSION=${CLUSTER}
    DOCKER_AGENT_IMG_NAME="antrea/antrea-agent-ubuntu"
    DOCKER_CONTROLLER_IMG_NAME="antrea/antrea-controller-ubuntu"
    docker save -o ${antrea_images_tar} ${DOCKER_AGENT_IMG_NAME}:${DOCKER_IMG_VERSION} ${DOCKER_CONTROLLER_IMG_NAME}:${DOCKER_IMG_VERSION}

    node_names=$(kubectl get nodes -o wide --no-headers=true | awk '{print $1}')
    for node_name in ${node_names}; do
        gcloud compute scp ${antrea_images_tar} ubuntu@${node_name}:~ --zone ${GKE_ZONE}
        gcloud compute ssh ubuntu@${node_name} --command="sudo ctr -n=k8s.io images import ~/${antrea_images_tar} ; sudo ctr -n=k8s.io images tag docker.io/${DOCKER_AGENT_IMG_NAME}:${DOCKER_IMG_VERSION} docker.io/${DOCKER_AGENT_IMG_NAME}:latest ; sudo ctr -n=k8s.io images tag docker.io/${DOCKER_CONTROLLER_IMG_NAME}:${DOCKER_IMG_VERSION} docker.io/${DOCKER_CONTROLLER_IMG_NAME}:latest" --zone ${GKE_ZONE}
    done
    rm ${antrea_images_tar}

    echo "=== Configuring Antrea for cluster ==="
    if [[ -n ${SVC_ACCOUNT_NAME+x} ]]; then
        gcloud projects add-iam-policy-binding ${GKE_PROJECT} --member serviceAccount:${SVC_ACCOUNT_NAME} --role roles/container.admin
        kubectl create clusterrolebinding cluster-admin-binding --clusterrole cluster-admin --user ${SVC_ACCOUNT_NAME}
    elif [[ -n ${USER_EMAIL+x} ]]; then
        gcloud projects add-iam-policy-binding ${GKE_PROJECT} --member user:${USER_EMAIL} --role roles/container.admin
        kubectl create clusterrolebinding cluster-admin-binding --clusterrole cluster-admin --user ${USER_EMAIL}
    elif [[ "$SKIP_IAM_POLICY_BINDING" == true ]]; then
        echo "Skipping the IAM Policy Binding for Cluster Management."
    else
        echo "Neither service account or user email info is set, cannot create cluster-admin-binding!"
        echo "Please refer to --help for more information."
        exit 1
    fi

    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke-node-init.yml
    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke.yml
    kubectl rollout status --timeout=2m deployment.apps/antrea-controller -n kube-system
    kubectl rollout status --timeout=2m daemonset/antrea-agent -n kube-system

    # Restart all Pods in all Namespaces (kube-system, gmp-system, etc) so they can be managed by Antrea.
    for ns in $(kubectl get ns -o=jsonpath=''{.items[*].metadata.name}'' --no-headers=true); do
        pods=$(kubectl get pods -n $ns -o custom-columns=NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{ print $1 }')
        [ -z "$pods" ] || kubectl delete pods -n $ns $pods
    done
    kubectl rollout status --timeout=2m deployment.apps/kube-dns -n kube-system
    # wait for other pods in the kube-system namespace to become ready
    sleep 5

    echo "=== Antrea has been deployed for GKE cluster ${CLUSTER} ==="
}

function run_conformance() {
    echo "=== Running Antrea Conformance and Network Policy Tests ==="

    # Allow nodeport traffic by external IP
    gcloud compute firewall-rules create allow-nodeport --allow tcp:30000-32767

    ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-conformance \
      --kubernetes-version ${KUBE_CONFORMANCE_IMAGE_VERSION} \
      --log-mode ${MODE} > ${GIT_CHECKOUT_DIR}/gke-test.log && \
    # Skip legacy NetworkPolicy tests
    ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-network-policy --e2e-skip "NetworkPolicyLegacy" \
      --kubernetes-version ${KUBE_CONFORMANCE_IMAGE_VERSION} \
      --log-mode ${MODE} >> ${GIT_CHECKOUT_DIR}/gke-test.log || \
    TEST_SCRIPT_RC=$?

    if [[ $TEST_SCRIPT_RC -eq 0 ]]; then
        echo "All tests passed."
        echo "=== SUCCESS !!! ==="
    elif [[ $TEST_SCRIPT_RC -eq 1 ]]; then
        echo "Failed test cases exist."
        echo "=== FAILURE !!! ==="
    else
        echo "Unexpected error when running tests."
        echo "=== FAILURE !!! ==="
    fi

    gcloud compute firewall-rules delete allow-nodeport

    echo "=== Cleanup Antrea Installation ==="
    kubectl delete -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke.yml --ignore-not-found=true || true
    kubectl delete -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-gke-node-init.yml --ignore-not-found=true || true
}

function cleanup_cluster() {
    echo '=== Cleaning up GKE cluster ${cluster} ==='
    # Do not exit automatically on error (to enable retries below)
    set +e
    retry=5
    while [[ "${retry}" -gt 0 ]]; do
       gcloud container clusters delete ${CLUSTER} --zone ${GKE_ZONE}
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
    set -e
    echo "=== Cleanup cluster ${CLUSTER} succeeded ==="
}

if [[ "$RUN_ALL" == true || "$RUN_SETUP_ONLY" == true ]]; then
    setup_gke
    deliver_antrea_to_gke
    run_conformance
fi

if [[ "$RUN_ALL" == true || "$RUN_CLEANUP_ONLY" == true ]]; then
    cleanup_cluster
fi

if [[ "$RUN_CLEANUP_ONLY" == false && $TEST_SCRIPT_RC -ne 0 ]]; then
    exit 1
fi
