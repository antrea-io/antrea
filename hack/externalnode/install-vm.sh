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

_usage="Usage: $0 [--ns <Namespace>] [--bin <AntreaAgentSavePath>] [--config <AgentConfigSavePath>] [--kubeconfig <KubeconfigSavePath>] [--antrea-kubeconfig <AntreaKubeconfigSavePath>] [--nodename <ExternalNodeName>] [--ovs-bridge <OVSBridgeName>] [--containerize] [--validate-ovs] [--antrea-version] [--help|-h]
        --ns                          Namespace to be used by the antrea-agent
        --bin                         Path of the antrea-agent binary
        --config                      Path of the antrea-agent configuration file
        --kubeconfig                  Path of the kubeconfig to access K8s API Server
        --antrea-kubeconfig           Path of the kubeconfig to access Antrea API Server
        --nodename                    ExternalNode name to be used by the antrea-agent
        --ovs-bridge                  Specify the OVS bridge name
        --validate-ovs                Validate OVS configuration and performs cleanup when any error is detected.
        --containerize                Run Antrea Agent in a container.
        --antrea-version              Specify the version of Antrea.
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
OVS_BIN="start_ovs"

# Antrea agent files
ANTREA_AGENT_BIN="antrea-agent"
ANTREA_AGENT_KUBECONFIG="antrea-agent.kubeconfig"
ANTREA_AGENT_ANTREA_KUBECONFIG="antrea-agent.antrea.kubeconfig"

# Docker variables
ANTREA_VERSION="latest"
ANTREA_DOCKER_REGISTRY="antrea/antrea-ubuntu"
ANTREA_DOCKER_IMAGE="${ANTREA_DOCKER_REGISTRY}:${ANTREA_VERSION}"

NODE_NAME="$(hostname)"
OS_NAME=""

declare -a SUPPORTED_OS=("ubuntu 18.04" "ubuntu 20.04" "rhel 8.4")

# List of supported OS versions, verified with Antrea.
check_supported_platform() {
    echo "Checking supported OS platform"
    OS_NAME=`grep -Po '^ID=\K.*' /etc/os-release | sed -e 's/^"//' -e 's/"$//'`
    os_version=`grep -Po '^VERSION_ID=\K.*' /etc/os-release | sed -e 's/^"//' -e 's/"$//'`
    dist_version="${OS_NAME} ${os_version}"
    for ver in "${SUPPORTED_OS[@]}"; do
        if [ "$ver" == "$dist_version" ]; then
            return
        fi
    done
    echoerr "${SUPPORTED_OS[*]} are supported"
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
    cp "$KUBECONFIG" "${AGENT_CONF_PATH}/${ANTREA_AGENT_KUBECONFIG}"
    chmod 600 "${AGENT_CONF_PATH}/${ANTREA_AGENT_KUBECONFIG}"
    if [[ ! -f "$ANTREA_KUBECONFIG" ]]; then
        echoerr "Error $ANTREA_KUBECONFIG file not found"
        exit 1
    fi
    echo "Copying $ANTREA_KUBECONFIG to $AGENT_CONF_PATH"
    cp "$ANTREA_KUBECONFIG" "${AGENT_CONF_PATH}/${ANTREA_AGENT_ANTREA_KUBECONFIG}"
    chmod 600 "${AGENT_CONF_PATH}/${ANTREA_AGENT_ANTREA_KUBECONFIG}"
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

# Generic function to execute command with timeout.
execute_command() {
    cmd="$1"
    timeout="$2"
    echo "Executing $cmd with timeout $timeout at $(date)"
    timeout --preserve-status --foreground $timeout $cmd
    ret=$?
    if [ $ret -ne 0 ]; then
        echoerr "$cmd failed with status $ret at $(date), exiting"
        exit 2
    fi
}

# Install Docker as container runtime.
install_container_runtime() {
    echo "Installing container runtime on $OS_NAME"
    case "$OS_NAME" in
        ubuntu)
        # Uninstall older versions of Docker.
        docker_uninstall_packages="docker docker-engine docker.io containerd runc"
        apt-get remove ${docker_uninstall_packages}
        cmd="apt-get update"
        execute_command "$cmd" 1m
        dependent_packages="ca-certificates curl gnupg lsb-release"
        cmd="apt-get install -y ${dependent_packages}"
        execute_command "$cmd" 1m
        docker_gpg_key="/usr/share/keyrings/docker-archive-keyring.gpg"
        rm -rf ${docker_gpg_key}
        docker_download_url="https://download.docker.com/linux/ubuntu"
        timeout --preserve-status --foreground 10s curl -fsSL ${docker_download_url}/gpg | sudo gpg --dearmor -o ${docker_gpg_key}
        # Setup a stable repository
        echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=${docker_gpg_key}] ${docker_download_url} \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        cmd="apt-get update"
        execute_command "$cmd" 1m
        docker_install_packages="docker-ce docker-ce-cli containerd.io docker-compose-plugin"
        cmd="apt-get install -y ${docker_install_packages}"
        execute_command "$cmd" 2m
        ;;
        rhel)
        # Uninstall older versions of Docker.
        docker_uninstall_packages="docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc"
        sudo yum remove ${docker_unistall_packages}
        cmd="sudo yum install -y yum-utils"
        execute_command "$cmd" 1m
        # We are using CentOs Docker images for Rhel as suggested in official website.
        docker_download_url="https://download.docker.com/linux/centos/docker-ce.repo"
        cmd="sudo yum-config-manager --add-repo ${docker_download_url}"
        execute_command "$cmd" 1m
        docker_install_packages="docker-ce docker-ce-cli containerd.io docker-compose-plugin"
        cmd="sudo yum install -y ${docker_install_packages}"
        execute_command "$cmd" 1m
        cmd="sudo systemctl start docker"
        execute_command "$cmd" 1m
        ;;
    esac
}

# Install all pre-requisite packages needed for installation.
install_prerequisite_packages() {
    set +eo pipefail
    # Install Docker, docker-compose only when running services in containers.
    docker version
    if [[ "$?" -ne 0 ]]; then
        install_container_runtime
    fi
    set -eo pipefail
}

# Create docker-compose file with OVS and antrea-agent container specific parameters.
create_docker_compose_file() {
    cat << EOF > $AGENT_CONF_PATH/docker-compose.yaml
version: "3"

services:
  antrea-ovs:
    image: $ANTREA_DOCKER_IMAGE
    container_name: antrea-ovs
    volumes:
        - /var/log/openvswitch:/var/log/openvswitch
        - /var/run/openvswitch:/var/run/openvswitch
        - /lib/modules:/lib/modules
    command: $OVS_BIN
    network_mode: host
    cap_add:
        - NET_ADMIN
        - SYS_NICE
        - SYS_ADMIN
        - IPC_LOCK
    deploy:
        restart_policy:
          condition: on-failure
          delay: 3s
          max_attempts: 500
          window: 10s

  antrea-agent:
    image: $ANTREA_DOCKER_IMAGE
    container_name: antrea-agent
    volumes:
        - /etc/antrea/:/etc/antrea
        - /var/run/antrea:/var/run/antrea
        - /var/run/openvswitch:/var/run/openvswitch
        - /var/log/antrea:/var/log/antrea
    environment:
        - NODE_NAME=$NODE_NAME
    command: $ANTREA_AGENT_BIN --config $AGENT_CONF_PATH/antrea-agent.conf --logtostderr=false --log_file=$AGENT_LOG_DIR/antrea-agent.log
    network_mode: host
    privileged: true
    deploy:
        restart_policy:
          condition: on-failure
          delay: 3s
          max_attempts: 500
          window: 10s
EOF
}

create_antrea_agent_service_file() {
    cat >$AGENT_CONF_PATH/antrea-agent.sh << 'EOF'
#!/bin/bash

AGENT_CONF_PATH="/etc/antrea"
AGENT_LOG_DIR="/var/log/antrea"
DOCKER_COMPOSE_YAML="$AGENT_CONF_PATH/docker-compose.yaml"

declare -a OVS_KERNEL_MODULES=("openvswitch")
declare -a CONTAINERS=("antrea-ovs" "antrea-agent")

load_ovs_modules() {
    for module in "${OVS_KERNEL_MODULES[@]}"; do
        lsmod | grep -q $module
        if [[ $? -ne 0 ]]; then
            echo "Load $module kernel module"
            modprobe $module
            if [ "$?" -ne 0 ]; then
                echoerr "Error loading kernel module $module"
            fi
        fi
    done
}

docker info
if [[ $? -ne 0 ]]; then
    echo "Starting Docker service"
    systemctl start docker
    sleep 2
fi

key=$1
case $key in
    start)
    load_ovs_modules
    docker compose -f $DOCKER_COMPOSE_YAML up -d
    ;;
    stop)
    docker compose -f $DOCKER_COMPOSE_YAML stop ${CONTAINERS[*]}
    ;;
esac
EOF
}

# Create antrea-agent service as a systemd service for monitoring/creating Antrea specific containers.
setup_antrea_agent_service() {
    DESCRIPTION="Antrea agent service to monitor OVS and antrea-agent containers"
    SERVICE_NAME="antrea-agent.service"
    IS_ACTIVE=$(sudo systemctl is-active $SERVICE_NAME)
    create_antrea_agent_service_file
    sudo chmod +x $AGENT_CONF_PATH/antrea-agent.sh
    if [ "$IS_ACTIVE" == "active" ]; then
        # restart the service
        echo "Systemd service $SERVICE_NAME is running"
        echo "Restarting $SERVICE_NAME service"
        sudo systemctl restart $SERVICE_NAME
    else
        # create service file
        echo "Creating systemd service file for $SERVICE_NAME"
        sudo cat > /etc/systemd/system/${SERVICE_NAME} << EOF
[Unit]
Description=$DESCRIPTION
After=network.target
[Service]
ExecStart=$AGENT_CONF_PATH/antrea-agent.sh start
ExecStop=$AGENT_CONF_PATH/antrea-agent.sh stop
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
        # restart daemon, enable and start service.
        echo "Reloading daemon and enabling service $SERVICE_NAME"
        sudo systemctl daemon-reload
        sudo systemctl enable ${SERVICE_NAME//'.service'/} # remove the extension.
        sudo systemctl start ${SERVICE_NAME//'.service'/}
        if [ $? -eq 0 ]; then
            echo "Antrea-agent service started successfully"
        else
            echoerr "Error Antrea-agent service could not be started"
            exit 1
        fi
    fi
}

# Function to deploy and run Antrea specific containers.
deploy_antrea_containers() {
    set +eo pipefail
    if [ -z "$(docker images -q $ANTREA_DOCKER_IMAGE)" ]; then
        echo "Downloading the Docker image $ANTREA_DOCKER_IMAGE"
        docker pull $ANTREA_DOCKER_IMAGE
        if [[ "$?" -ne 0 ]]; then
            echoerr "Error, Downloading the Docker image $ANTREA_DOCKER_IMAGE"
            exit 2
        fi
    else
        echo "$ANTREA_DOCKER_IMAGE image is already loaded to Docker"
    fi
    # Start Antrea/OVS containers as part of system startup.
    setup_antrea_agent_service

    set -eo pipefail
}

# To validate if any errors in OVS bridge config and delete the bridge.
check_ovs_config_and_cleanup() {
    bridges=$(ovs-vsctl list-br)
    for br in $bridges; do
        if [ "$br" != "$OVS_BRIDGE" ]; then
            continue
        fi
        # Check if any of the interface is in error state.
        ports=$(ovs-vsctl list-ports $OVS_BRIDGE)
        for port in $ports; do
            output=$(ovs-vsctl --no-headings --columns=error list interface "$port")
            if [ "$output" != '[]' ]; then
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
    --containerize)
    CONTAINERIZE=true
    shift 1
    ;;
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
    --antrea-version)
    ANTREA_VERSION="$2"
    ANTREA_DOCKER_IMAGE="${ANTREA_DOCKER_REGISTRY}:${ANTREA_VERSION}"
    validate_argument $1 $2
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

# Check whether OVS configuration needs to be cleaned up.
if [ "$VALIDATE_OVS_CONFIG" = true ] && [ -z "$CONTAINERIZE" ]; then
    check_ovs_config_and_cleanup
    exit 0
fi

validate_mandatory_arguments() {
    if [ -z "$CONFIG_PATH" ] || [ -z "$KUBECONFIG" ] || [ -z "$ANTREA_KUBECONFIG" ] || ( [ -z "$AGENT_BIN_PATH" ] && [ -z "$CONTAINERIZE" ] ); then
        echoerr "Missing argument(s)"
        print_usage
        exit 1
    fi
}

validate_mandatory_arguments
check_supported_platform
copy_antrea_agent_files
update_antrea_agent_conf
if [ -z "$CONTAINERIZE" ]; then
    start_antrea_agent_service
else
    install_prerequisite_packages
    create_docker_compose_file
    deploy_antrea_containers
fi
