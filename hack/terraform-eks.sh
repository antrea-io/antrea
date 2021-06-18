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

# NOTE: terraform environment variables need to be set
AWS_CLI="aws"
TERRAFORM="terraform"
KUBECTL="kubectl"
AWS_IAM="aws-iam-authenticator"
RUN_PATH="$HOME/tmp/terraform-eks"
if [[ $(uname) == "Darwin" ]]; then
  READLINK="greadlink"
else
  READLINK="readlink"
fi
CMD_ARRAY=($AWS_CLI $TERRAFORM $KUBECTL $AWS_IAM pv bzip2 jq $READLINK)
ENV_ARRAY=(TF_VAR_eks_cluster_iam_role_name TF_VAR_eks_iam_instance_profile_name TF_VAR_eks_key_pair_name)

_usage="Usage: $0 :
                [create]  : create eks cluster
                [destroy] : destroy eks cluster
                [kubectl] : access eks
                [load] : load container image from local machine to eks cluster
                [--help|h]"

function print_help {
    echo "Try '$0 --help' for more information."
}

function print_usage {
    echo "$_usage"
}

function validate {
  for cmd in ${CMD_ARRAY[@]}; do
     command -v $cmd > /dev/null 2>&1
     if [ $? -ne 0 ]; then
       echo $cmd not found, please install first
       exit 1
     fi
  done

  for env in ${ENV_ARRAY[@]}; do
     printenv $env > /dev/null 2>&1
     if [ $? -ne 0 ]; then
       echo required environment variable $env is not set.
       exit 1
     fi
  done

  # check for aws permissions
  $AWS_CLI eks list-clusters > /dev/null 2>&1
   if [ $? -ne 0 ]; then
     echo aws user has no permission to eks
     exit 1
   fi

  $AWS_CLI iam list-roles > /dev/null 2>&1
   if [ $? -ne 0 ]; then
     echo aws user has no permission to iam
     exit 1
   fi
}

function apply {
  validate
  CONFIG_PATH=$(dirname $($READLINK -f "$0"))/terraform/eks
  mkdir -p $RUN_PATH
  if [ $? -ne 0 ]; then
     echo $RUN_PATH cannot be created
     exit 1
  fi
  cp $CONFIG_PATH/*.tf $RUN_PATH
  cd $RUN_PATH
  $TERRAFORM init
  if [ $? -ne 0 ]; then
     exit 1
  fi
  echo "yes" | $TERRAFORM apply
  if [[ $? -ne 0 ]]; then
    echo "eks creation failed"
    exit 1
  fi
  echo eks cluster created.
  $TERRAFORM output kubectl_config > $RUN_PATH/kubeconfig
  echo run eks kubectl ... to acess it.
}

function destroy {
  validate
  if [ ! -d $RUN_PATH ]; then
    exit 0
  fi
  cd $RUN_PATH
  echo "yes" | $TERRAFORM destroy
}

function load {
  validate
  image=$1
  nodes=$(KUBECONFIG=$RUN_PATH/kubeconfig kubectl get nodes -o json | jq -r '.items[] | .status | .addresses[] | select(.type == "ExternalIP") |.address')
  for node in $(echo $nodes); do
    echo load $image to $node
    docker save $image | bzip2 |pv| ssh  -oStrictHostKeyChecking=no ec2-user@$node 'docker load'
  done
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    create)
      apply
      exit 0
    ;;
    destroy)
      destroy
      exit 0
    ;;
    kubectl)
      KUBECONFIG=$RUN_PATH/kubeconfig kubectl ${@:2}
      exit $?
    ;;
    load)
      load $2
      exit $?
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *)    # unknown option
    echo "Unknown option $1"
    exit 1
    ;;
esac
done
