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
                  [--sriov-interface <interface name>] [--sriov-vf-count <count>] [--host-name <name>]

Configure/cleanup SR-IOV VFs and deploy the SR-IOV device plugin at the remote single node cluster.

        --setup                                 Configures the SR-IOV VFs and deploy the SR-IOV device plugin at the remote cluster (single node cluster).
        --cleanup                               cleanup SR-IOV device plugin and VFs at the remote cluster (single node cluster).
        --sriov-interface <interface name>      Base network interface (remote node scope) to create VFs.
        --sriov-vf-count <count>                Number of virtual functions to be created on the base network interface.
        --host-name <k8s control node name/IP>  K8s cluster's host name or IP address."

_ssh_config_info="Prerequisite: Kubernetes(K8s) cluster is up and running at the local or remote server.

Follow these steps to configure SSH information to access the kubernetes cluster control node.

1) Update remote/local cluster control node information at your /home/<user>/.ssh/config
Example:
Host <Control-Plane-Node>
    HostName <Control-Plane-IP>
    Port 22
    user ubuntu
    IdentityFile /home/ubuntu/.ssh/id_rsa

2) Add remote/local server's public key (id_rsa.pub) to /home/<user>/.ssh/authorized_keys.

3) Set PubkeyAuthentication at sshd_config to yes at your remote/local server.

4) Ensure SSH to the remote/local node works after the above configuration (ssh <control node/host name>)"

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


SRIOV_PLUGIN_REL_TAG=v3.5.1
export URL_SRIOV_DP_CONFIG_MAP="https://raw.githubusercontent.com/k8snetworkplumbingwg/sriov-network-device-plugin/$SRIOV_PLUGIN_REL_TAG/deployments/configMap.yaml"
export URL_SRIOV_DP_DAEMONSET="https://raw.githubusercontent.com/k8snetworkplumbingwg/sriov-network-device-plugin/$SRIOV_PLUGIN_REL_TAG/deployments/k8s-v1.16/sriovdp-daemonset.yaml"
export YAML_ANTREA='antrea.yml'

sriov_interface=''
vfs_num=''
action=''
configure=''
hostName=''

function validateOptions() {
        if [ -z $configure ]; then
                echoerr "--setup or --cleanup must be provided. Configuration failed."
                exit 1
        fi
        if [ "$sriov_interface" != '' ] && [ -z $vfs_num ]; then
                echoerr "Base interface provided without SR-IOV VF counts. Configuration failed."
                exit 1
        elif [ -z $sriov_interface ] && [ "$vfs_num" != '' ]; then
                echoerr "SR-IOV VF counts provided without base interface. Configuration failed."
                exit 1
        fi
        #If interface and vfs_num is provided, ensure that the base interface (with VF ability) is present at the remote cluster.
        if [ "$sriov_interface" != '' ] && [ "$vfs_num" != '' ]; then
                if [[ $hostName = '' ]]; then
                       echoerr "Host Name/IP must be providied . Configuration failed."
                       exit 1
                fi
                ssh $hostName <<EOF
                   export interface=$sriov_interface
                   $(declare -f checkInterface)
                   checkInterface
EOF
               if [ $? -eq 255 ]; then
                     echoerr "SSH to $hostName failed. Ensure ssh configuration needs are met"
                     print_ssh_config_info
                     exit 1
               elif [ $? -eq 0 ]; then
                     echoerr "Interface $sriov_interface doesn't exist at the given host. Configuration failed."
                     exit 1
               fi
        fi
}
#This function is not required to be called if the --interface-name and --sriov-vf-count params are not provided.
function checkInterface() {
        if [[ ! -d /sys/class/net/$sriov_interface ]]; then
                echoerr "ERROR: No interface named $sriov_interface exist on the machine, please check the interface name."
                exit 1
        fi
}
#This function is not required to be called if the --interface-name and --sriov-vf-count params are not provided.
function setIPLinkDown() {
        checkInterface
        ip link set $sriov_interface down
        if [ $? -ne 0 ]; then
                echoerr "Failed to set Ip link down!"
                exit 1
        fi
}
#This function is not required to be called if the --interface-name and --sriov-vf-count params are not provided.
function configureVFs() {
        checkInterface
        if [[ $(cat /sys/class/net/$sriov_interface/device/sriov_numvfs) != 0 ]]; then
                echo "0" >/sys/class/net/$sriov_interface/device/sriov_numvfs
                sleep 2
        fi
        if [[ $configure -eq true ]]; then
                echo "$vfs_num" >/sys/class/net/$sriov_interface/device/sriov_numvfs
                cat /sys/class/net/$sriov_interface/device/sriov_numvfs
        else
                echo "0" >/sys/class/net/$sriov_interface/device/sriov_numvfs
                cat /sys/class/net/$sriov_interface/device/sriov_numvfs
        fi
}
#This function is not required to be called if the --interface-name and --sriov-vf-count params were not provided.
function setIPLinkUp() {
        checkInterface
        ip link set $sriov_interface up
        if [ $? -ne 0 ]; then
                echoerr "Failed to set Ip link up!"
                exit 1
        fi
        ifconfig $sriov_interface
}

#This function is not required to be called if the --interface-name and --sriov-vf-count params were not provided.
function SriovDevicePlugin() {
        kubectl $action -f $URL_SRIOV_DP_CONFIG_MAP
        if [ $? -ne 0 ]; then
                echoerr "Failed to $action SR-IOV Device Plugin- configMap.yaml"
                exit 1
        fi

        kubectl $action -f $URL_SRIOV_DP_DAEMONSET
        if [ $? -ne 0 ]; then
                echoerr "Failed $action SR-IOV Device Plugin - sriovdp-daemonset.yaml"
                exit 1
        fi
        echo "$action ConfigMap and SriovDevicePlugin done!"
}
function updateKubeConfigForTargetCluster() {
        mkdir -p /tmp/kubernetes/$hostName
        scp $hostName:/etc/kubernetes/admin.conf /tmp/kubernetes/$hostName/.
        if [ $? -ne 0 ]; then
                echoerr "Failed to copy the downloaded configuration files!"
                exit 1
        fi
        export KUBECONFIG=/tmp/kubernetes/$hostName/admin.conf
}


function configureSriovOnRemoteCluster() {
        if [ ! -z $sriov_interface ] && [ ! -z $vfs_num ]; then
                if [[ $hostName != '' ]]; then
                        ssh vcesd2 <<EOF
                        export sriov_interface=$sriov_interface vfs_num=$vfs_num
                        $(declare -f echoerr checkInterface setIPLinkDown configureVFs setIPLinkUp)
                        setIPLinkDown
                        configureVFs
                        setIPLinkUp
EOF
                else
                        echoerr "HostName must be provided for SR-IOV based secondary network configuration."
                        exit 1
                fi
                SriovDevicePlugin
        fi
        if [[ $configure == "true" ]]; then
        echo "SR-IOV successfully configured at the remote server."
        else
        echo "SR-IOV successfully deconfigured at the remote server."
        fi
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
        --sriov-interface)
                sriov_interface="$2"
                shift 2
                ;;
        --sriov-vf-count)
                vfs_num="$2"
                shift 2
                ;;
        --host-name)
                hostName="$2"
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

validateOptions
#Get the remote cluster's config file and update $KUBECONFIG
if [[ $hostName != '' ]]; then
        updateKubeConfigForTargetCluster
fi
#Configure the all the secondary network pre-requisites
configureSriovOnRemoteCluster
