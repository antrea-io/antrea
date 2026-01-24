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

set -eu

function echoerr {
    >&2 echo "$@"
}

CLUSTER=""
REGION="us-west-2"
K8S_VERSION="1.31"
AWS_NODE_TYPE="t3.medium"
SSH_KEY_PATH="$HOME/.ssh/id_rsa.pub"
SSH_PRIVATE_KEY_PATH="$HOME/.ssh/id_rsa"
RUN_ALL=true
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
RUN_GARBAGE_COLLECTION=false
GC_CLUSTER_AGE_HOURS=3
KUBECONFIG_PATH="$HOME/jenkins/out/eks"
MODE="report"
TEST_SCRIPT_RC=0
KUBE_CONFORMANCE_IMAGE_VERSION=auto
INSTALL_EKSCTL=true
AWS_SERVICE_USER_ROLE_ARN=""
AWS_DURATION_SECONDS=7200

_usage="Usage: $0 [--cluster-name <EKSClusterNameToUse>] [--kubeconfig <KubeconfigSavePath>] [--k8s-version <ClusterVersion>]\
                  [--aws-access-key <AccessKey>] [--aws-secret-key <SecretKey>] [--aws-region <Region>]\
                  [--aws-service-user-role-arn <ServiceUserRoleARN>] [--ssh-key <SSHKey] [--ssh-private-key <SSHPrivateKey] [--log-mode <SonobuoyResultLogLevel>]\
                  [--setup-only] [--cleanup-only] [--gc-cluster] [--gc-cluster-age-hours <Hours>]

Setup a EKS cluster to run K8s e2e community tests (Conformance & Network Policy).

        --cluster-name                The cluster name to be used for the generated EKS cluster. Must be specified if not run in Jenkins environment.
        --kubeconfig                  Path to save kubeconfig of generated EKS cluster.
        --k8s-version                 EKS K8s cluster version. Defaults to $K8S_VERSION.
        --aws-access-key              AWS Acess Key for logging in to awscli.
        --aws-secret-key              AWS Secret Key for logging in to awscli.
        --aws-service-user-role-arn   AWS Service User Role ARN for logging in to awscli.
        --aws-region                  The AWS region where the cluster will be initiated. Defaults to us-east-2.
        --ssh-key                     The path of key to be used for ssh access to worker nodes.
        --log-mode                    Use the flag to set either 'report', 'detail', or 'dump' level data for sonobuoy results.
        --setup-only                  Only perform setting up the cluster and run test.
        --cleanup-only                Only perform cleaning up the cluster.
        --gc-cluster                  Cleanup old EKS clusters and CloudFormation stacks (for periodic maintenance).
        --gc-cluster-age-hours        Age threshold in hours for garbage collection. Defaults to 3.
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
    --gc-cluster)
    RUN_GARBAGE_COLLECTION=true
    RUN_ALL=false
    shift
    ;;
    --gc-cluster-age-hours)
    GC_CLUSTER_AGE_HOURS="$2"
    shift 2
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
    export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY
    export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_KEY

    export AWS_DEFAULT_OUTPUT=json
    export AWS_DEFAULT_REGION=$REGION
    if [[ "$AWS_SERVICE_USER_ROLE_ARN" != "" ]]; then
      # Use AWS CLI to assume an IAM role and obtain temporary security credentials
      # Source: AWS CLI Command Reference - https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html
      # When --duration-seconds is NOT specified, AWS uses DEFAULT VALUE: 3600 seconds (1 hour)
      # Source: AWS STS AssumeRole API Documentation -
      # https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_RequestParameters
      # "By default, the value is set to 3600 seconds."
      # From previous observations, this Jenkins job process has taken over an hour, usually within 1 hour and 10 minutes,
      # so it's set to 2 hours here.
        TEMP_CRED=$(aws sts assume-role \
          --role-arn "$AWS_SERVICE_USER_ROLE_ARN" \
          --role-session-name "aws-cli-session-$(date +%s)" \
          --duration-seconds $AWS_DURATION_SECONDS \
          --query "Credentials" \
          --output json)

        # Handle assume-role errors immediately
        if [ $? -ne 0 ] || [ -z "$TEMP_CRED" ]; then
          echo "ERROR: Failed to assume role $AWS_SERVICE_USER_ROLE_ARN"
          exit 1
        fi

        export AWS_ACCESS_KEY_ID=$(echo "$TEMP_CRED" | jq -r .AccessKeyId)
        export AWS_SECRET_ACCESS_KEY=$(echo "$TEMP_CRED" | jq -r .SecretAccessKey)
        export AWS_SESSION_TOKEN=$(echo "$TEMP_CRED" | jq -r .SessionToken)

        # Clear sensitive variables from memory
        unset AWS_ACCESS_KEY AWS_SECRET_KEY TEMP_CRED
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
    docker image prune -af --filter "until=2h" > /dev/null
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

function clusters_gc() {
    echo "=== Starting EKS garbage collection in region ${REGION} ==="
    echo "Cleaning up clusters older than ${GC_CLUSTER_AGE_HOURS} hours"

    GC_CLUSTER_AGE_SECONDS=$((GC_CLUSTER_AGE_HOURS * 3600))
    CURRENT_TIME=$(date +%s)

    clusters=$(aws eks list-clusters --region ${REGION} --query 'clusters' --output json | jq -r '.[]')

    if [ -z "$clusters" ]; then
        echo "No EKS clusters found in region ${REGION}"
        return 0
    fi

    deleted_count=0
    skipped_count=0
    failed_count=0

    for cluster in $clusters; do
        # Skip clusters that don't match our naming pattern
        if [[ ! "$cluster" =~ ^cloud-antrea-eks- ]]; then
            echo "Skipping cluster $cluster (does not match naming pattern)"
            skipped_count=$((skipped_count + 1))
            continue
        fi

        creation_time=$(aws eks describe-cluster --region ${REGION} --name ${cluster} --query 'cluster.createdAt' --output text)

        if [ -z "$creation_time" ]; then
            echo "WARNING: Could not determine creation time for cluster $cluster"
            failed_count=$((failed_count + 1))
            continue
        fi

        creation_time=$(date -d "$creation_time" +%s)

        if [ -z "$creation_time" ]; then
            echo "WARNING: Could not parse creation time for cluster $cluster"
            failed_count=$((failed_count + 1))
            continue
        fi

        cluster_age_seconds=$((CURRENT_TIME - creation_time))
        cluster_age_hours=$((cluster_age_seconds / 3600))

        if [ $cluster_age_seconds -gt $GC_CLUSTER_AGE_SECONDS ]; then
            echo "Found old cluster: $cluster (age: ${cluster_age_hours}h, created: $creation_time)"
            echo "Deleting cluster: $cluster"

            set +e
            retry=3
            while [[ "${retry}" -gt 0 ]]; do
                CLUSTER=$cluster
                cleanup_cluster
                if [[ $? -eq 0 ]]; then
                    echo "Successfully deleted cluster: $cluster"
                    deleted_count=$((deleted_count + 1))
                    break
                fi
                echo "Failed to delete cluster $cluster, retrying... (${retry} attempts left)"
                sleep 10
                retry=$((retry - 1))
            done

            if [[ "${retry}" -eq 0 ]]; then
                echo "ERROR: Failed to delete EKS cluster ${cluster} after multiple attempts"
            fi
            set -e
        else
            echo "Cluster $cluster is recent (age: ${cluster_age_hours}h), skipping"
            skipped_count=$((skipped_count + 1))
        fi
    done

    echo "=== EKS cleanup summary: ${deleted_count} clusters deleted, ${skipped_count} clusters skipped, ${failed_count} clusters creation time parse failed ==="

    # Check for residual CloudFormation stacks
    echo "=== Checking for residual CloudFormation stacks ==="
    stacks=$(aws cloudformation list-stacks --region ${REGION} --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries[*].[StackName,CreationTime]' --output json)

    set +e
    echo "$stacks" | jq -c '.[]' | while read -r stack_info; do
        stack_name=$(echo "$stack_info" | jq -r '.[0]')
        stack_creation_time=$(echo "$stack_info" | jq -r '.[1]')

        # Only process eksctl-created stacks for antrea clusters
        if [[ ! "$stack_name" =~ ^eksctl-cloud-antrea-eks- ]]; then
            continue
        fi

        stack_creation_epoch=$(date -d "$stack_creation_time" +%s)

        if [ -z "$stack_creation_epoch" ]; then
            echo "WARNING: Could not parse creation time for stack $stack_name"
            continue
        fi

        stack_age_seconds=$((CURRENT_TIME - stack_creation_epoch))
        stack_age_hours=$((stack_age_seconds / 3600))

        if [ $stack_age_seconds -gt $GC_CLUSTER_AGE_SECONDS ]; then
            echo "Found old CloudFormation stack: $stack_name (age: ${stack_age_hours}h)"
            echo "Deleting CloudFormation stack: $stack_name"
            aws cloudformation delete-stack --region ${REGION} --stack-name ${stack_name}
            if [[ $? -eq 0 ]]; then
                echo "Successfully initiated deletion of stack: $stack_name"
            else
                echo "ERROR: Failed to delete CloudFormation stack: $stack_name"
            fi
        fi
    done
    set -e

    echo "=== EKS garbage collection completed ==="
}

# ensures that the script can be run from anywhere
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
GIT_CHECKOUT_DIR=${THIS_DIR}/..
pushd "$THIS_DIR" > /dev/null

source ${THIS_DIR}/jenkins/utils.sh

function start_timeout_watcher() {
    local timeout_seconds=$1
    local parent_pid=$2

    local safe_timeout=$((timeout_seconds - 300))

    echo "Timeout watcher started. Will signal after ${safe_timeout} seconds."

    sleep $safe_timeout

    echo "Process timed out before AWS credential expiration! Sending termination signal to main process (PID: $parent_pid)"
    kill -SIGTERM $parent_pid 2>/dev/null || true
}

start_timeout_watcher "$AWS_DURATION_SECONDS" $$ &
timeout_watcher_pid=$!

if [[ "$RUN_GARBAGE_COLLECTION" == true ]]; then
    trap "kill -9 $timeout_watcher_pid 2>/dev/null || true" EXIT
    clusters_gc
    exit 0
fi

if [[ "$RUN_SETUP_ONLY" != true ]]; then
    trap "kill -9 $timeout_watcher_pid 2>/dev/null ; cleanup_cluster" EXIT
else
    trap "kill -9 $timeout_watcher_pid 2>/dev/null || true" EXIT
fi

if [[ "$RUN_ALL" == true || "$RUN_SETUP_ONLY" == true ]]; then
    setup_eks
    deliver_antrea_to_eks
    run_conformance
fi

if [[ "$RUN_CLEANUP_ONLY" == false && $TEST_SCRIPT_RC -ne 0 ]]; then
    exit 1
fi
