#!/usr/bin/env bash
# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

pushd $THIS_DIR

_usage="Usage: $0 [--setup] [--cleanup]
                  [--network <sriov>] [--host-name <name>] [--help]

Deploy Antrea CNI and its native secondary network prerequisites on an existing/running K8s cluster control node.

        --setup                                 Deploy all the pre-requisite plugins and CRDs for secondary network configuration.
        --cleanup                               Remove all the pre-requisite plugins and CRDs deployed for secondary network configuration.
        --network                               Secondary network type, can be sriov or vlan.
        --host-name <k8s control node name/IP>  K8s cluster control node's host name or IP address."

_ssh_config_info="Prerequisite: Kubernetes(K8s) cluster is up and running at the local or remote server.

Follow these steps to configure SSH information to access the kubernetes cluster.

1) Update remote/local cluster control node information at your /home/<user>/.ssh/config
Example:
Host <Control-Plane-Node>
    HostName <Control-Plane-IP>
    Port 22
    user ubuntu
    IdentityFile /home/ubuntu/.ssh/id_rsa

2) Add remote/local cluster control node's public key (id_rsa.pub) to /home/<user>/.ssh/authorized_keys

3) Set PubkeyAuthentication at sshd_config to yes at your remote/local cluster control node

4) Esure SSH to the remote/local node works after the above configuration (ssh <control node/host name>)"

function echoerr {
        echo >&2 "$@"
}

function print_usage {
        echoerr "$_usage"
}

function print_ssh_config_info {
        echoerr "$_ssh_config_info"
}

function print_help {
        echoerr "Try '$0 --help' for more information."
}

NAMESPACE="kube-system"
ANTREA_DS="ds/antrea-agent"
export YAML_ANTREA='antrea.yml'
export YAML_NET_ATTACH_DEF_CRD='network-attachment-definition-crd.yml'
export YAML_SECONDARY_NETWORKS='secondary-networks.yml'

action=''
configure=''
hostName=''
network=''

function generateAntreaConfig() {
        genManifest=$THIS_DIR/../../../hack/generate-manifest.sh
        echo $genManifest
        if [ "$1" == "sriov" ]; then
                $genManifest --sriov --extra-helm-values "featureGates.SecondaryNetwork=true" > $YAML_ANTREA
        elif [ "$1" == "vlan" ]; then
                $genManifest --extra-helm-values "featureGates.SecondaryNetwork=true" > $YAML_ANTREAc
        else
              echoerr "Incorrect network option $1. Failed to generate antrea.yml"
              exit 1
        fi

        if [ $? -ne 0 ]; then
              echoerr "Failed to generate antrea.yml"
              exit 1
        fi
        echo "antrea.yml successfully generated with the required secondary network configuration parameters."
}


function AntreaCNI() {
        kubectl $action -f $YAML_ANTREA
        if [ $? -ne 0 ]; then
              echoerr "Failed to $action Antrea CNI"
              exit 1
        fi
        # Setting timeout to report lack of progress after set time is elapsed
        kubectl patch $ANTREA_DS -p '{"spec":{"progressDeadlineSeconds":30}}' -n $NAMESPACE
        kubectl -n $NAMESPACE rollout status $ANTREA_DS
}

function VirtualNetworks() {
        kubectl $action -f $YAML_SECONDARY_NETWORKS
        if [ $? -ne 0 ]; then
                echoerr "Failed to $action Virtual Network Instance: $instance"
                exit 1
        fi
        echo " $action VirtualNetworks Done!"
}

function NetworkAttachmentDefinition() {
        kubectl $action -f $YAML_NET_ATTACH_DEF_CRD
        if [ $? -ne 0 ]; then
                echoerr "Failed to $action Network Attachment Definition CRD- network-attachment-definition-crd.yaml"
                exit 1
        fi
        if [ $action == "apply" ]; then
             VirtualNetworks
        fi
        echo "$action of NetworkAttachmentDefinition and the Virtual network instances Done!"
}

function configureSecondaryNetworkPrerequisite() {
        NetworkAttachmentDefinition
        AntreaCNI
        echo "Setup is up and running..."
}

if [[ $# -eq 0 ]]; then
        echoerr "--setup or --cleanup must be provided. Execution failed."
        print_usage
        exit 1
fi
while [[ $# -gt 0 ]]; do
        key="$1"
        if [[ -z $2 ]]; then
                if [[ $key != "--setup" ]] && [[ $key != "--cleanup" ]] && [[ $key != "--help" ]] ; then
                        echoerr "$key <value> not provided."
                        print_usage
                        exit 1
                fi
        fi
        case $key in
        --setup)
                action="apply"
                configure=true
                shift 1
                ;;
        --cleanup)
                action="delete"
                configure=false
                shift 1
                ;;
        --host-name)
                hostName="$2"
                shift 2
                ;;
        --network)
                network=$2
                shift 2
                ;;
        --help)
                print_usage
                exit 0
                ;;
        *) # unknown option
                echoerr "Unknown option $1"
                exit 1
                ;;
        esac
done

# Download all the prerequisite files.
if [[ $configure == true ]]; then
        # Generate antrea.yml with --sriov config option.
        generateAntreaConfig $network
fi
configureSecondaryNetworkPrerequisite
