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

_usage="Usage: $0 [--ns <NameSpace>] [--bin <AntreaAgentSavePath>] [--config <AgentConfigSavePath>] [--kubeconfig <KubeconfigSavePath>] [--antrea-kubeconfig <AntreaKubeconfigSavePath>] [--nodename <ExternalNodeName>] [--help|-h]
        --ns                          NameSpace to be used by the antrea-agent.
        --bin                         Path of the antrea-agent binary
        --config                      Path of the antrea-agent configuration file
        --kubeconfig                  Path of the kubeconfig to access K8s API Server
        --antrea-kubeconfig           Path of the kubeconfig to access Antrea API Server
        --nodename                    ExternalNode name to be used by the antrea-agent
        --help, -h                    Print this message and exit"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

INSTALL_PATH="/usr/sbin"
AGENT_BIN_PATH=""
CONFIG_PATH=""
KUBECONFIG=""
ANTREAKUBECONFIG=""
AGENT_NAMESPACE=""
NODE_NAME="$(hostname)"
AGENT_LOG_DIR="/var/log/antrea"
AGENT_CONF_PATH="/etc/antrea"

check_supported_platform() {
  echo "Checking platform supported"
  if ! [[ $(lsb_release -rs) =~ ^(18.04|20.04)$ ]]; then
    echoerr "Error only Ubuntu 18.04/20.04 version is supported"
    exit 1
  fi
}

copy_antrea_agent_files() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
      echoerr "Error $CONFIG_PATH file not found"
      exit 1
    fi
    mkdir -p $AGENT_CONF_PATH
    echo "Copying $CONFIG_PATH to $AGENT_CONF_PATH"
    cp $CONFIG_PATH $AGENT_CONF_PATH

    if [[ ! -f "$KUBECONFIG" ]]; then
      echoerr "Error $KUBECONFIG file not found"
      exit 1
    fi

    echo "Copying $KUBECONFIG to $AGENT_CONF_PATH"
    cp "$KUBECONFIG" "${AGENT_CONF_PATH}/antrea-agent.kubeconfig"

    if [[ ! -f "$ANTREA_KUBECONFIG" ]]; then
      echoerr "Error $ANTREA_KUBECONFIG file not found"
      exit 1
    fi
    echo "Copying $ANTREA_KUBECONFIG to $AGENT_CONF_PATH"
    cp "$ANTREA_KUBECONFIG" "${AGENT_CONF_PATH}/antrea-agent.antrea.kubeconfig"
}

update_antrea_agent_conf() {
  echo "Updating clientConnection and antreaClientConnection"
  sed -i "s|kubeconfig: |kubeconfig: $AGENT_CONF_PATH/|g" $AGENT_CONF_PATH/antrea-agent.conf
  echo "Updating externalNodeNamespace to $AGENT_NAMESPACE"
  sed -i "s|#externalNodeNamespace: default|externalNodeNamespace: $AGENT_NAMESPACE|g" $AGENT_CONF_PATH/antrea-agent.conf
}

start_antrea_agent_service() {
    if [[ ! -f "$AGENT_BIN_PATH" ]]; then
      echoerr "Error $AGENT_BIN_PATH file not found"
      exit 1
    fi
    mkdir -p $AGENT_LOG_DIR
    mkdir -p $INSTALL_PATH
    cp "$AGENT_BIN_PATH" "$INSTALL_PATH"
cat << EOF > /etc/systemd/system/antrea-agent.service
Description="antrea-agent as a systemd service"
After=network.target
[Service]
Environment="NODE_NAME=$NODE_NAME"
ExecStart=$INSTALL_PATH/antrea-agent \
--config=$AGENT_CONF_PATH/antrea-agent.conf \
--logtostderr=false \
--log_file=$AGENT_LOG_DIR/antrea-agent.log
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable antrea-agent
    echo "Starting antrea-agent service"
    sudo systemctl start antrea-agent
    sudo systemctl status antrea-agent
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

check_supported_platform
copy_antrea_agent_files
update_antrea_agent_conf
start_antrea_agent_service
