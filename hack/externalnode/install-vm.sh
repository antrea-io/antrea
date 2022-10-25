#!/usr/bin/env bash

# Copyright 2022 Antrea Authors
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

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--ns <Namespace>] [--bin <AntreaAgentSavePath>] [--config <AgentConfigSavePath>] [--kubeconfig <KubeconfigSavePath>] [--antrea-kubeconfig <AntreaKubeconfigSavePath>] [--nodename <ExternalNodeName>] [--ovs-bridge <OVSBridgeName>] [--validate-ovs] [--help|-h]
        --ns                          Namespace to be used by the antrea-agent
        --bin                         Path of the antrea-agent binary
        --config                      Path of the antrea-agent configuration file
        --kubeconfig                  Path of the kubeconfig to access K8s API Server
        --antrea-kubeconfig           Path of the kubeconfig to access Antrea API Server
        --nodename                    ExternalNode name to be used by the antrea-agent
        --ovs-bridge                  Specify the OVS bridge name
        --validate-ovs                Validate OVS configuration and performs cleanup when any error is detected.
        --help, -h                    Print this message and exit

Please run the script as sudo user"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

INSTALL_PATH="/usr/sbin"
ANTREA_AGENT="antrea-agent"
AGENT_LOG_DIR="/var/log/antrea"
AGENT_CONF_PATH="/etc/antrea"
OVS_BRIDGE="br-int"
OVS_VSWITCHD="ovs-vswitchd.service"

# Optional arguments
VALIDATE_OVS_CONFIG=false
NODE_NAME="$(hostname)"

# List of supported OS versions, verified by antrea.
declare -a SUPPORTED_OS=("Ubuntu 18.04" "Ubuntu 20.04" "Red Hat Enterprise Linux 8.4")

check_supported_platform() {
  echo "Checking supported OS platform"
  os_name=`grep -Po '^NAME=\K.*' /etc/os-release | sed -e 's/^"//' -e 's/"$//'`
  os_version=`grep -Po '^VERSION_ID=\K.*' /etc/os-release | sed -e 's/^"//' -e 's/"$//'`
  dist_version="${os_name} ${os_version}"
  for ver in "${SUPPORTED_OS[@]}"; do
      if [ "$ver" == "$dist_version" ]; then
          return
      fi
  done
  echoerr "Error ${SUPPORTED_OS[*]} are supported"
  exit 1
}

copy_antrea_agent_files() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
        echoerr "Error $CONFIG_PATH file not found"
        exit 1
    fi
    mkdir -p $AGENT_CONF_PATH
    echo "Copying $CONFIG_PATH to $AGENT_CONF_PATH"
    cp "$CONFIG_PATH" $AGENT_CONF_PATH

    if [[ ! -f "$KUBECONFIG" ]]; then
        echoerr "Error $KUBECONFIG file not found"
        exit 1
    fi

    echo "Copying $KUBECONFIG to $AGENT_CONF_PATH"
    cp "$KUBECONFIG" "${AGENT_CONF_PATH}/antrea-agent.kubeconfig"
    chmod 600 "${AGENT_CONF_PATH}/antrea-agent.kubeconfig"

    if [[ ! -f "$ANTREA_KUBECONFIG" ]]; then
        echoerr "Error $ANTREA_KUBECONFIG file not found"
        exit 1
    fi
    echo "Copying $ANTREA_KUBECONFIG to $AGENT_CONF_PATH"
    cp "$ANTREA_KUBECONFIG" "${AGENT_CONF_PATH}/antrea-agent.antrea.kubeconfig"
    chmod 600 "${AGENT_CONF_PATH}/antrea-agent.antrea.kubeconfig"
}

update_antrea_agent_conf() {
  echo "Updating clientConnection and antreaClientConnection"
  sed -i "s|kubeconfig: |kubeconfig: $AGENT_CONF_PATH/|g" $AGENT_CONF_PATH/antrea-agent.conf
  if [[ -z "$AGENT_NAMESPACE" ]]; then
      AGENT_NAMESPACE="default"
  fi
  echo "Updating externalNodeNamespace to $AGENT_NAMESPACE"
  sed -i "s|#externalNodeNamespace: default|externalNodeNamespace: $AGENT_NAMESPACE|g" $AGENT_CONF_PATH/antrea-agent.conf
  echo "Updating ovsBridge to $OVS_BRIDGE"
  sed -i "s|#ovsBridge: br-int|ovsBridge: $OVS_BRIDGE|g" $AGENT_CONF_PATH/antrea-agent.conf
}

start_antrea_agent_service() {
    if [[ ! -f "$AGENT_BIN_PATH" ]]; then
        echoerr "Error $AGENT_BIN_PATH file not found"
        exit 1
    fi
    mkdir -p $AGENT_LOG_DIR
    mkdir -p $INSTALL_PATH
    cp "$AGENT_BIN_PATH" "$INSTALL_PATH"
    echo "Copying $BASH_SOURCE to ${AGENT_CONF_PATH}/install-vm.sh"
    cp "$BASH_SOURCE" "${AGENT_CONF_PATH}/install-vm.sh"
    chmod +x "${AGENT_CONF_PATH}/install-vm.sh"
    cat >/etc/systemd/system/antrea-agent.service << EOF
[Unit]
Description="antrea-agent as a systemd service"
After=network.target
[Service]
Environment="NODE_NAME=$NODE_NAME"
ExecStartPre=${AGENT_CONF_PATH}/install-vm.sh --validate-ovs --ovs-bridge $OVS_BRIDGE
ExecStart=$INSTALL_PATH/antrea-agent \
--config=$AGENT_CONF_PATH/antrea-agent.conf \
--logtostderr=false \
--log_file=$AGENT_LOG_DIR/antrea-agent.log
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$ANTREA_AGENT"
    echo "Starting ${ANTREA_AGENT} service"
    systemctl start "$ANTREA_AGENT"
    systemctl status "$ANTREA_AGENT"
}

check_ovs_config_and_cleanup() {
    bridges=$(ovs-vsctl list-br)
    for br in $bridges; do
        if [ "$br" != "$OVS_BRIDGE" ] ; then
            continue
        fi
        # Check if any of the interface is in error state.
        ports=$(ovs-vsctl list-ports $OVS_BRIDGE)
        for port in $ports; do
            output=$(ovs-vsctl --no-headings --columns=error list interface "$port")
            if [ "$output" != '[]' ] ; then
                echoerr "Error while listing interface $port, deleting bridge $OVS_BRIDGE"
                ovs-vsctl del-br "$OVS_BRIDGE"
                break
            fi
        done
        exit 0
    done
}

validate_argument() {
    if [[ $2 == --* || -z $2 ]]; then
        echoerr "Error invalid argument for $1: <$2>"
        print_usage
        exit 1
    fi
}

while [[ $# -gt 0 ]]
do
key="$1"
case $key in
    --ns)
    AGENT_NAMESPACE="$2"
    validate_argument $1 $2
    shift 2
    ;;
    --bin)
    AGENT_BIN_PATH="$2"
    validate_argument $1 $2
    shift 2
    ;;
    --config)
    CONFIG_PATH="$2"
    validate_argument $1 $2
    shift 2
    ;;
    --kubeconfig)
    KUBECONFIG="$2"
    validate_argument $1 $2
    shift 2
    ;;
    --antrea-kubeconfig)
    ANTREA_KUBECONFIG="$2"
    validate_argument $1 $2
    shift 2
    ;;
    --nodename)
    NODE_NAME="$2"
    validate_argument $1, $2
    shift 2
    ;;
    --ovs-bridge)
    OVS_BRIDGE="$2"
    shift 2
    ;;
    --validate-ovs)
    VALIDATE_OVS_CONFIG=true
    shift 1
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

# Check whether OVS configuration needs to be cleaned up.
if [ "$VALIDATE_OVS_CONFIG" = true ] ; then
    check_ovs_config_and_cleanup
    exit 0
fi

# Check for mandatory arguments.
if [ -z "$AGENT_BIN_PATH" ] || [ -z "$CONFIG_PATH" ] || [ -z "$KUBECONFIG" ] || [ -z "$ANTREA_KUBECONFIG" ] ; then
    echoerr "Missing argument(s)"
    print_usage
    exit 1
fi

check_supported_platform
copy_antrea_agent_files
update_antrea_agent_conf
start_antrea_agent_service
