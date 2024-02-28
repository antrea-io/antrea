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

CLUSTER=""
REGION="us-west-2"
K8S_VERSION="1.27"
AWS_NODE_TYPE="t3.medium"
SSH_KEY_PATH="$HOME/.ssh/id_rsa.pub"
SSH_PRIVATE_KEY_PATH="$HOME/.ssh/id_rsa"
RUN_ALL=true
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
KUBECONFIG_PATH="$HOME/jenkins/out/eks"
MODE="report"
TEST_SCRIPT_RC=0
KUBE_CONFORMANCE_IMAGE_VERSION=auto
INSTALL_EKSCTL=true
AWS_SERVICE_USER_ROLE_ARN=""
AWS_SERVICE_USER_NAME=""

_usage="Usage: $0 [--cluster-name <EKSClusterNameToUse>] [--kubeconfig <KubeconfigSavePath>] [--k8s-version <ClusterVersion>]\
                  [--aws-access-key <AccessKey>] [--aws-secret-key <SecretKey>] [--aws-region <Region>] [--aws-service-user <ServiceUserName>]\
                  [--aws-service-user-role-arn <ServiceUserRoleARN>] [--ssh-key <SSHKey] [--ssh-private-key <SSHPrivateKey] [--log-mode <SonobuoyResultLogLevel>]\
                  [--setup-only] [--cleanup-only]

Setup a EKS cluster to run K8s e2e community tests (Conformance & Network Policy).

        --cluster-name                The cluster name to be used for the generated EKS cluster. Must be specified if not run in Jenkins environment.
        --kubeconfig                  Path to save kubeconfig of generated EKS cluster.
        --k8s-version                 EKS K8s cluster version. Defaults to $K8S_VERSION.
        --aws-access-key              AWS Acess Key for logging in to awscli.
        --aws-secret-key              AWS Secret Key for logging in to awscli.
        --aws-service-user-role-arn   AWS Service User Role ARN for logging in to awscli.
        --aws-service-user            AWS Service User Name for logging in to awscli.
        --aws-region                  The AWS region where the cluster will be initiated. Defaults to us-east-2.
        --ssh-key                     The path of key to be used for ssh access to worker nodes.
        --log-mode                    Use the flag to set either 'report', 'detail', or 'dump' level data for sonobuoy results.
        --setup-only                  Only perform setting up the cluster and run test.
        --cleanup-only                Only perform cleaning up the cluster.
        --skip-eksctl-install         Do not install the latest eksctl version. Eksctl must be installed already."

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
    --aws-service-user-role-arn)
    AWS_SERVICE_USER_ROLE_ARN="$2"
    shift 2
    ;;
    --aws-service-user)
    AWS_SERVICE_USER_NAME="$2"
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
    --ssh-private-key)
    SSH_PRIVATE_KEY_PATH="$2"
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
    --skip-eksctl-install)
    INSTALL_EKSCTL=false
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

if [[ "$CLUSTER" == "" ]]; then
    echoerr "--cluster-name is required"
    exit 1
fi

function generate_eksctl_config() {
    AMI_ID=$(aws ssm get-parameter \
                 --name /aws/service/eks/optimized-ami/${K8S_VERSION}/amazon-linux-2/recommended/image_id \
                 --query "Parameter.Value" --output text)

    cat > eksctl-containerd.yaml <<EOF
---
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER}
  region: ${REGION}
  version: "${K8S_VERSION}"
managedNodeGroups:
  - name: containerd
    instanceType: ${AWS_NODE_TYPE}
    desiredCapacity: 2
    ami: ${AMI_ID}
    amiFamily: AmazonLinux2
    ssh:
      allow: true
      publicKeyPath: ${SSH_KEY_PATH}
    overrideBootstrapCommand: |
      #!/bin/bash
      /etc/eks/bootstrap.sh ${CLUSTER} --container-runtime containerd
EOF
    echo "eksctl-containerd.yaml"
}

function setup_eks() {

    echo "=== This cluster to be created is named: ${CLUSTER} ==="
    # Save the cluster information for cleanup on Jenkins environment
    echo "CLUSTERNAME=${CLUSTER}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
    if [[ -n ${ANTREA_GIT_REVISION+x} ]]; then
        echo "ANTREA_REPO=${ANTREA_REPO}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
        echo "ANTREA_GIT_REVISION=${ANTREA_GIT_REVISION}" > ${GIT_CHECKOUT_DIR}/ci_properties.txt
    fi
    echo "=== Using the following awscli version ==="
    aws --version

    set +e
    if [[ "$AWS_SERVICE_USER_ROLE_ARN" != "" ]] && [[ "$AWS_SERVICE_USER_NAME" != "" ]]; then
        mkdir -p ~/.aws
        cat > ~/.aws/config <<EOF
[default]
region = $REGION
role_arn = $AWS_SERVICE_USER_ROLE_ARN
source_profile = $AWS_SERVICE_USER_NAME
output = json
EOF
        cat > ~/.aws/credentials <<EOF
[$AWS_SERVICE_USER_NAME]
aws_access_key_id = $AWS_ACCESS_KEY
aws_secret_access_key = $AWS_SECRET_KEY
EOF
    elif [[ "$AWS_SERVICE_USER_ROLE_ARN" = "" ]] && [[ "$AWS_SERVICE_USER_NAME" = "" ]]; then
        mkdir -p ~/.aws
        cat > ~/.aws/config <<EOF
[default]
region = $REGION
output = json
EOF
        cat > ~/.aws/credentials <<EOF
[default]
aws_access_key_id = $AWS_ACCESS_KEY
aws_secret_access_key = $AWS_SECRET_KEY
EOF
    else
        echo "Invalid input either specify both aws-service-user-role-arn and aws-service-user or none."
        exit 1
    fi

    if [[ "$INSTALL_EKSCTL" == true ]]; then
        echo "=== Installing latest version of eksctl ==="
        curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
        sudo mv /tmp/eksctl /usr/local/bin
    fi
    set -e
    printf "\n"
    echo "=== Using the following eksctl ==="
    which eksctl
    echo "=== Using the following kubectl ==="
    which kubectl

    echo '=== Creating a cluster in EKS ==='
    config="$(generate_eksctl_config)"
    eksctl create cluster -f $config
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

    kubectl get nodes -o wide --no-headers=true | awk '{print $7}' | while read IP; do
        scp -o StrictHostKeyChecking=no -i ${SSH_PRIVATE_KEY_PATH} ${antrea_images_tar} ec2-user@${IP}:~
        ssh -o StrictHostKeyChecking=no -i ${SSH_PRIVATE_KEY_PATH} -n ec2-user@${IP} "sudo ctr -n=k8s.io images import ~/${antrea_images_tar} ; sudo ctr -n=k8s.io images tag docker.io/${DOCKER_AGENT_IMG_NAME}:${DOCKER_IMG_VERSION} docker.io/${DOCKER_AGENT_IMG_NAME}:latest --force ; sudo ctr -n=k8s.io images tag docker.io/${DOCKER_CONTROLLER_IMG_NAME}:${DOCKER_IMG_VERSION} docker.io/${DOCKER_CONTROLLER_IMG_NAME}:latest --force"
    done
    rm ${antrea_images_tar}

    echo "=== Configuring Antrea for cluster ==="
    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-eks-node-init.yml
    kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea-eks.yml
    kubectl rollout status --timeout=2m deployment.apps/antrea-controller -n kube-system
    kubectl rollout status --timeout=2m daemonset/antrea-agent -n kube-system

    echo "=== Antrea has been deployed for EKS cluster ${CLUSTER} ==="
}

function run_conformance() {
    echo "=== Running Antrea Conformance and Network Policy Tests ==="

    # Skip NodePort related cases for EKS since by default eksctl does not create security groups for nodeport service
    # access through node external IP. See https://github.com/antrea-io/antrea/issues/690
    skip_regex="\[Slow\]|\[Serial\]|\[Disruptive\]|\[Flaky\]|\[Feature:.+\]|\[sig-cli\]|\[sig-storage\]|\[sig-auth\]|\[sig-api-machinery\]|\[sig-apps\]|\[sig-node\]|\[sig-instrumentation\]|NodePort"
    ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-conformance --e2e-skip ${skip_regex} \
      --kubernetes-version ${KUBE_CONFORMANCE_IMAGE_VERSION} \
      --log-mode ${MODE} > ${GIT_CHECKOUT_DIR}/eks-test.log && \
    # Skip legacy NetworkPolicy tests
    ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-network-policy --e2e-skip "NetworkPolicyLegacy" \
      --kubernetes-version ${KUBE_CONFORMANCE_IMAGE_VERSION} \
      --log-mode ${MODE} >> ${GIT_CHECKOUT_DIR}/eks-test.log || \
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

    echo "=== Cleanup Antrea Installation ==="
    for antrea_yml in ${GIT_CHECKOUT_DIR}/build/yamls/*.yml
    do
        kubectl delete -f ${antrea_yml} --ignore-not-found=true || true
    done
}

function cleanup_cluster() {
    echo '=== Cleaning up EKS cluster ${CLUSTER} ==='
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
GIT_CHECKOUT_DIR=${THIS_DIR}/..
pushd "$THIS_DIR" > /dev/null

source ${THIS_DIR}/jenkins/utils.sh

if [[ "$RUN_ALL" == true || "$RUN_SETUP_ONLY" == true ]]; then
    setup_eks
    deliver_antrea_to_eks
    run_conformance
fi

if [[ "$RUN_ALL" == true || "$RUN_CLEANUP_ONLY" == true ]]; then
    cleanup_cluster
fi

if [[ "$RUN_CLEANUP_ONLY" == false && $TEST_SCRIPT_RC -ne 0 ]]; then
    exit 1
fi
