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

REGION="us-east-2"
K8S_VERSION="1.15"
AWS_NODE_TYPE="t3.medium"
SSH_KEY_PATH="$HOME/.ssh/id_rsa.pub"
RUN_ALL=true
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
RUN_CLEANUP_ONLY=false
KUBECONFIG_PATH="$HOME/jenkins/out/"
TEST_FAILURE=false

_usage="Usage: $0 [--cluster-name <EKSClusterNameToUse>] [--kubeconfig <KubeconfigSavePath>] [--k8s-version <ClusterVersion>]\
                  [--aws-access-key <AccessKey>] [--aws-secret-key <SecretKey>] [--aws-region <Region>] [--ssh-key <SSHKey] \
                  [--setup-only] [--cleanup-only]"

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
    --aws-access-key)
    AWS_ACCESS_KEY="$2"
    shift 2
    ;;
    --aws-secret-key)
    AWS_SECRET_KEY="$2"
    shift 2
    ;;
    --aws-region)
    REGION="$2"
    shift 2
    ;;
    --ssh-key)
    SSH_KEY_PATH="$2"
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

if [[ -z ${CLUSTER+x} ]]; then
    if [[ -z ${JOB_NAME+x} ]]; then
        echoerr "Use --cluster-name to set the name of the EKS cluster"
        exit 1
    fi
    CLUSTER="${JOB_NAME}-${BUILD_NUMBER}"
fi

function setup_eks() {

    echo "=== This cluster to be created is named: ${CLUSTER} ==="
    echo "CLUSTERNAME=${CLUSTER}" > ci_properties.txt

    echo "=== Using the following awscli version ==="
    aws --version

    set +e
    aws configure << EOF
${AWS_ACCESS_KEY}
${AWS_SECRET_KEY}
${REGION}
JSON
EOF
    set -e
    printf "\n"
    echo "=== Using the following kubectl ==="
    which kubectl

    echo '=== Creating a cluster in EKS ==='
    eksctl create cluster \
      --name ${CLUSTER} --region ${REGION} --version=${K8S_VERSION} \
      --nodegroup-name workers --node-type ${AWS_NODE_TYPE} --nodes 2 \
      --ssh-access --ssh-public-key ${SSH_KEY_PATH} \
      --managed
    if [[ $? -ne 0 ]]; then
        echo "=== Failed to deploy EKS cluster! ==="
        exit 1
    fi

    mkdir -p ${KUBECONFIG_PATH}
    eksctl utils write-kubeconfig --region ${REGION} \
      --cluster=${CLUSTER} --kubeconfig=${KUBECONFIG_PATH}/kubeconfig
    export KUBECONFIG="${KUBECONFIG_PATH}/kubeconfig"

    sleep 5
    if [[ $(kubectl get svc) ]]; then
        echo "=== EKS cluster setup succeeded ==="
    else
        echo "=== EKS kubectl is not configured correctly! ==="
        exit 1
    fi
}

function deliver_antrea_to_eks() {

    echo "=== Configuring Antrea for cluster ==="

    # EKS service CIDR is currently assigned by AWS,
    # either from 172.20.0.0/16 or 10.100.0.0/16 depending on the range of VPC
    # https://forums.aws.amazon.com/thread.jspa?messageID=859958
    k8s_svc_addr=$(kubectl get svc -A | grep kubernetes | awk '{print $4}')

    if [[ $k8s_svc_addr == 10.100.* ]]; then
    	 k8s_svc_cidr='10.100.0.0/16'
    elif [[ $k8s_svc_addr == 172.20.* ]]; then
    	 k8s_svc_cidr='172.20.0.0/16'
    else
    	 echo "Cannot determine EKS serviceCIDR!"
         exit 1
    fi

    set +e
    worker_node_ip_1=$(kubectl get nodes -o wide | sed -n '2 p' | awk '{print $7}')
    node_mtu=$(ssh -o StrictHostKeyChecking=no -l "ec2-user" $worker_node_ip_1 \
      'export PATH=$PATH:/usr/sbin; ip a | grep -E eth0.*mtu | cut -d " " -f5')

    sed -i.bak -e "s|#defaultMTU: 1450|defaultMTU: ${node_mtu}|g" ../build/yamls/antrea-eks.yml
    sed -i.bak -e "s|#serviceCIDR: 10.96.0.0/12|serviceCIDR: ${k8s_svc_cidr}|g" ../build/yamls/antrea-eks.yml
    echo "defaultMTU set as ${node_mtu}"
    echo "seviceCIDR set as ${k8s_svc_cidr}"

    kubectl apply -f ../build/yamls/antrea-eks.yml
    set -e

    kubectl rollout status --timeout=2m deployment.apps/antrea-controller -n kube-system
    kubectl rollout status --timeout=2m daemonset/antrea-agent -n kube-system

    echo "=== Antrea has been deployed for EKS cluster ${CLUSTER} ==="
}

function run_conformance() {
    echo "=== Running Antrea Conformance and Network Policy Tests ==="

    ./run-k8s-e2e-tests.sh --e2e-conformance --e2e-network-policy > eks-test.log

    if grep -Fxq "Failed tests:" eks-test.log
    then
        echo "Failed cases exist."
        TEST_FAILURE=true
    else
        echo "All tests passed."
    fi

    echo "=== Cleanup Antrea Installation ==="
    for antrea_yml in ../build/yamls/*.yml
    do
        kubectl delete -f ${antrea_yml} --ignore-not-found=true || true
    done

    if [[ "$TEST_FAILURE" == false ]]; then
        echo "=== SUCCESS !!! ==="
    fi
    echo "=== FAILURE !!! ==="
}

function cleanup_cluster() {
    echo '=== Cleaning up EKS cluster ${cluster} ==='
    retry=5
    while [[ "${retry}" -gt 0 ]]; do
       eksctl delete cluster --name ${CLUSTER} --region $REGION
       if [[ $? -eq 0 ]]; then
         break
       fi
       sleep 10
       retry=$((retry-1))
    done
    if [[ "${retry}" -eq 0 ]]; then
       echo "=== Failed to delete EKS cluster ${CLUSTER}! ==="
       exit 1
    fi
    rm -f ${KUBECONFIG_PATH}/kubeconfig
    echo "=== Cleanup cluster ${CLUSTER} succeeded ==="
}

# ensures that the script can be run from anywhere
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$THIS_DIR" > /dev/null

if [[ "$RUN_ALL" == true || "$RUN_SETUP_ONLY" == true ]]; then
    setup_eks
    deliver_antrea_to_eks
    run_conformance
fi

if [[ "$RUN_ALL" == true || "$RUN_CLEANUP_ONLY" == true ]]; then
    cleanup_cluster
fi

if [[ "$RUN_CLEANUP_ONLY" == false &&  "$TEST_FAILURE" == true ]]; then
    exit 1
fi
