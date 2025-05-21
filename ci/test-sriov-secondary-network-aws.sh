#!/bin/bash
# Copyright 2025 Antrea Authors.
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

TIMEOUT="10m"
AWS_DURATION_SECONDS=7200
K8S_VERSION="v1.32"
# Set AWS related variables
REGION="us-west-2"  # AWS region
INSTANCE_TYPE="c3.large"  # EC2 instance type
AMI_ID="ami-05d38da78ce859165"  # AMI ID for Ubuntu 24.04

RUN_ALL=true
RUN_SETUP_ONLY=false

SUBNET_CIDR_RES_ID="${SUBNET_CIDR_RES_ID:-}"

_usage="Usage: $0 [--aws-access-key <AccessKey>] [--aws-secret-key <SecretKey>] \
                  [--aws-security-group-id <SecurityGroupID>] [--aws-subnet-id <SubnetID>] \
                  [--aws-ec2-ssh-key-name <SSHKeyName>]
                  [--aws-service-user-role-arn <ServiceUserRoleARN>] \
                  [--aws-region <Region>] [--k8s-version <ClusterVersion>]

Setup a Kubernetes cluster and test SR-IOV secondary network in AWS.

        --aws-access-key              AWS Acess Key for logging in to awscli.
        --aws-secret-key              AWS Secret Key for logging in to awscli.
        --aws-security-group-id       Security group for the ec2 instance in the Kubernetes cluster.
        --aws-subnet-id               The subnet in which the ec2 instance network interface is located.
        --aws-ec2-ssh-key-name        The key name to be used for ssh access to ec2 instances.
        --aws-service-user-role-arn   AWS Service User Role ARN for logging in to awscli.
        --aws-region                  The AWS region where the cluster will be initiated. Defaults to $REGION.
        --setup-only                  Only perform setting up the cluster and run test.
        --cleanup-only                Only perform cleaning up the cluster.
        --k8s-version                 The K8s cluster version. Defaults to $K8S_VERSION."

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
    --aws-access-key)
    AWS_ACCESS_KEY="$2"
    shift 2
    ;;
    --aws-secret-key)
    AWS_SECRET_KEY="$2"
    shift 2
    ;;
    --aws-security-group-id)
    AWS_SECURITY_GROUP="$2"
    shift 2
    ;;
    --aws-subnet-id)
    AWS_SUBNET_ID="$2"
    shift 2
    ;;
    --aws-ec2-ssh-key-name)
    AWS_EC2_SSH_KEY_NAME="$2"
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
    RUN_SETUP_ONLY=false
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

set +e
export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_KEY
export AWS_DEFAULT_REGION=$REGION

# Use AWS CLI to assume an IAM role and obtain temporary security credentials
# Source: AWS CLI Command Reference - https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html
# When --duration-seconds is NOT specified, AWS uses DEFAULT VALUE: 3600 seconds (1 hour)
# Source: AWS STS AssumeRole API Documentation -
# https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_RequestParameters
# "By default, the value is set to 3600 seconds."
TEMP_CRED=$(aws sts assume-role \
  --role-arn "$AWS_SERVICE_USER_ROLE_ARN" \
  --duration-seconds $AWS_DURATION_SECONDS \
  --role-session-name "aws-cli-session-$(date +%s)" \
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

set -e

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ANTREA_CHART="$THIS_DIR/../build/charts/antrea"
ANTREA_TAR="antrea-ubuntu.tar"
DOCKER_IMAGE_PATH="$THIS_DIR/../$ANTREA_TAR"
SRIOV_SECONDARY_NETWORKS_YAML="$THIS_DIR/../test/e2e-secondary-network/infra/sriov-secondary-networks.yml"
IP_POOL_YAML="pool1.yaml"
NETATTACH_YAML="$THIS_DIR/../test/e2e-secondary-network/infra/sriov-network-attachment-definition.yml"

CONTROLPLANE_IP=""
WORKER_IP=""

CONTROLPLANE_INSTANCE_ID="${CONTROLPLANE_INSTANCE_ID:-}"
WORKER_INSTANCE_ID="${WORKER_INSTANCE_ID:-}"

CONTROLPLANE_NODE_ENI="${CONTROLPLANE_NODE_ENI:-}"
WORKER_NODE_ENI="${WORKER_NODE_ENI:-}"

# Function to launch EC2 instance
function launch_ec2_instance() {
    local instance_name=$1
    instance_id=$(aws ec2 run-instances \
        --image-id $AMI_ID \
        --count 1 \
        --instance-type $INSTANCE_TYPE \
        --key-name "$AWS_EC2_SSH_KEY_NAME" \
        --security-group-ids "$AWS_SECURITY_GROUP" \
        --subnet-id "$AWS_SUBNET_ID" \
        --block-device-mappings DeviceName=/dev/sda1,Ebs={VolumeSize=20} \
        --query "Instances[0].InstanceId" \
        --output text)
    echo "$instance_id"
}

function attach_network_interface() {
    local instance_id=$1
    local node_type=$2
    ENI_ID=$(aws ec2 create-network-interface \
      --subnet-id "$AWS_SUBNET_ID" \
      --groups "$AWS_SECURITY_GROUP" \
      --query 'NetworkInterface.NetworkInterfaceId' \
      --output text)

    echo "Network interface created successfully with ENI ID: $ENI_ID"

    #  Attach the ENI to the EC2 instance
    echo "Attaching network interface $ENI_ID to instance $instance_id ..."
    ATTACHMENT_ID=$(aws ec2 attach-network-interface \
      --network-interface-id "$ENI_ID" \
      --instance-id "$instance_id" \
      --device-index 1 \
      --query 'AttachmentId' \
      --output text)

    echo "Network interface attached successfully with Attachment ID: $ATTACHMENT_ID"

    if [[ "$node_type" == "control-plane" ]]; then
        CONTROLPLANE_NODE_ENI="$ENI_ID"
        echo "Assigned ENI ID $ENI_ID to CONTROLPLANE_NODE_ENI"
    elif [[ "$node_type" == "worker" ]]; then
        WORKER_NODE_ENI="$ENI_ID"
        echo "Assigned ENI ID $ENI_ID to WORKER_NODE_ENI."
    else
        echo "Invalid node type. Please specify 'control-plane' or 'worker'."
        exit 1
    fi

    echo "Verifying the attachment..."
    aws ec2 describe-instances \
      --instance-id "$instance_id" \
      --query "Reservations[0].Instances[0].NetworkInterfaces" \
      --output text
}

# Function to get the public IP of an EC2 instance
function get_instance_ip() {
    local instance_id=$1
    ip=$(aws ec2 describe-instances \
        --instance-ids "$instance_id" \
        --query "Reservations[0].Instances[0].PublicIpAddress" \
        --output text)
    echo "$ip"
}

# Function to install Kubernetes on a node
function install_kubernetes() {
    local node_ip=$1
    retry_count=20
    until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@"$node_ip" exit; do
      echo "SSH connection failed. Retrying in 10 seconds..."
      sleep 10
      retry_count=$((retry_count-1))
      if [ $retry_count -le 0 ]; then
          echo "Max retries reached. Exiting."
          exit 1
      fi
    done
    echo "Installing Kubernetes on node $node_ip..."
    ssh -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@"$node_ip" << EOF
        sudo apt update && sudo apt upgrade -y
        sudo apt install -y docker.io
        sudo docker --version

        sudo apt-get update
        sudo apt-get install apt-transport-https ca-certificates curl gpg -y

        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
        echo   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" |   sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update
        sudo apt-get install containerd.io -y
        sudo mkdir -p /etc/containerd
        sudo containerd config default | sudo tee /etc/containerd/config.toml
        sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

        sudo systemctl restart containerd
        sudo systemctl enable containerd

        echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$K8S_VERSION/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
        curl -fsSL https://pkgs.k8s.io/core:/stable:/$K8S_VERSION/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
        sudo apt update
        sudo apt install -y kubelet kubeadm kubectl
        sudo apt-mark hold kubelet kubeadm kubectl
        sudo swapoff -a
        sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
        sudo kubeadm version
EOF
}

# Function to initialize the Kubernetes control-plane node
function initialize_control_plane_node() {
    local control_plane_node_ip=$1
    echo "Initializing Kubernetes control-plane node on $control_plane_node_ip..."

    ssh -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@"$control_plane_node_ip" << EOF
        sudo kubeadm init --pod-network-cidr=10.244.0.0/16
        mkdir -p \$HOME/.kube
        sudo cp -i /etc/kubernetes/admin.conf \$HOME/.kube/config
        sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config
EOF
}

# Function to get the join command for the worker node
function get_join_command() {
    local control_plane_node_ip=$1
    join_command=$(ssh -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@"$control_plane_node_ip" "sudo kubeadm token create --print-join-command")
    echo "$join_command"
}

# Function to join the worker node to the cluster
function join_worker() {
    local worker_ip=$1
    local join_command=$2
    echo "Joining worker node with IP $worker_ip to the Kubernetes cluster..."

    ssh -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@$worker_ip << EOF
        sudo $join_command
EOF
}

# Function to verify the Kubernetes cluster status
function verify_cluster() {
    local control_plane_node_ip=$1
    echo "Verifying Kubernetes cluster status on control-plane node $control_plane_node_ip..."

    ssh -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@$control_plane_node_ip << EOF
        kubectl get nodes
EOF
}

function setup_cluster {
    # Launch Master and Worker EC2 instances
    echo "Launching EC2 instance ..."
    CONTROLPLANE_INSTANCE_ID=$(launch_ec2_instance "ControlPlane")
    echo "ControlPlane EC2 instance launched with Instance ID: $CONTROLPLANE_INSTANCE_ID"
    WORKER_INSTANCE_ID=$(launch_ec2_instance "Worker")
    echo "Worker EC2 instance launched with Instance ID: $WORKER_INSTANCE_ID"

    # Wait for EC2 instances to be fully running
    echo "Waiting for EC2 instances to be running..."
    aws ec2 wait instance-running --instance-ids $CONTROLPLANE_INSTANCE_ID $WORKER_INSTANCE_ID

    attach_network_interface "$CONTROLPLANE_INSTANCE_ID" "control-plane"
    attach_network_interface "$WORKER_INSTANCE_ID" "worker"

    echo "======== CONTROLPLANE_INSTANCE_ID: $CONTROLPLANE_INSTANCE_ID, WORKER_INSTANCE_ID: $WORKER_INSTANCE_ID ========="

    # Get the public IP addresses of the instances
    CONTROLPLANE_IP=$(get_instance_ip "$CONTROLPLANE_INSTANCE_ID")
    echo "Get PublicIpAddress of EC2 Instance $CONTROLPLANE_INSTANCE_ID: $CONTROLPLANE_IP"
    WORKER_IP=$(get_instance_ip "$WORKER_INSTANCE_ID")
    echo "Get PublicIpAddress of EC2 Instance $WORKER_INSTANCE_ID: $WORKER_IP"

    echo "====== CONTROLPLANE_IP: $CONTROLPLANE_IP, WORKER_IP: $WORKER_IP ======"

    # Install Kubernetes on both control-plane and worker nodes
    install_kubernetes "$CONTROLPLANE_IP"
    install_kubernetes "$WORKER_IP"

    # Initialize Kubernetes on control-plane Node
    initialize_control_plane_node "$CONTROLPLANE_IP"

    # Get the join command and join the worker node to the cluster
    JOIN_COMMAND=$(get_join_command "$CONTROLPLANE_IP")
    join_worker "$WORKER_IP" "$JOIN_COMMAND"

    # Verify the Kubernetes cluster status
    verify_cluster "$CONTROLPLANE_IP"

    echo "Kubernetes cluster setup completed!"
}

function build_image() {
    ./hack/build-antrea-linux-all.sh --pull
    docker save antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest -o $ANTREA_TAR
}

# Function to upload Docker image and load it
function upload_and_load_image() {
    local node_ip=$1
    local image_path=$2
    echo "Uploading Docker image $image_path to node $node_ip..."

    # Copy the Docker image tarball to the node
    scp -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" "$image_path" ubuntu@"$node_ip":/home/ubuntu/

    # SSH into the node and load the image
    ssh -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@"$node_ip" << EOF
        sudo ctr -n=k8s.io images import /home/ubuntu/$(basename "$image_path")
        sudo crictl images | grep antrea
        # remove the tarball after loading
        sudo rm /home/ubuntu/$(basename "$image_path")
EOF
}

function deploy_antrea() {
    echo "Deploy antrea on cluster..."
    helm install antrea "$ANTREA_CHART" --namespace kube-system --set featureGates.SecondaryNetwork=true
    kubectl rollout status --timeout=2m deployment.apps/antrea-controller -n kube-system
    kubectl rollout status --timeout=2m daemonset/antrea-agent -n kube-system
    kubectl get node -owide
    kubectl get pods -A
}

# Specify the output config file
SSH_CONFIG_FILE=$THIS_DIR/"k8s_nodes_config"
KUBECONFIG_FILE=$THIS_DIR/"remote.kube"
: > "$SSH_CONFIG_FILE"
: > "$KUBECONFIG_FILE"

# Function to get the node IP and name, then write to a config file.
function generate_ssh_config() {
    # Get the nodes' names and their external IPs
    scp -o StrictHostKeyChecking=no -i "$AWS_EC2_SSH_KEY_NAME" ubuntu@"$CONTROLPLANE_IP":/home/ubuntu/.kube/config "$KUBECONFIG_FILE"
    export KUBECONFIG=$KUBECONFIG_FILE
    kubectl get nodes -o wide | tail -n +2 | while read -r line; do
        # Extract node name and IP address
        NODE_NAME=$(echo "$line" | awk '{print $1}')
        NODE_IP=$(echo "$line" | awk '{print $6}')

        # Write the SSH configuration to the file
        # shellcheck disable=SC2129
        echo -e "Host $NODE_NAME" >> "$SSH_CONFIG_FILE"
        echo -e "\tHostName $NODE_IP" >> "$SSH_CONFIG_FILE"
        echo -e "\tPort 22" >> "$SSH_CONFIG_FILE"
        echo -e "\tUser ubuntu" >> "$SSH_CONFIG_FILE"
        echo -e "\tIdentityFile $THIS_DIR/../$AWS_EC2_SSH_KEY_NAME" >> "$SSH_CONFIG_FILE"
    done

    echo "SSH config written to $SSH_CONFIG_FILE"
}

function create_ippool_and_network_attachment_definition() {
    subnet_info=$(aws ec2 describe-subnets --subnet-ids "$AWS_SUBNET_ID" --query 'Subnets[0].{CIDR:CidrBlock}' --output json)
    subnet_cidr=$(echo "$subnet_info" | jq -r '.CIDR')

    # Ensure valid CIDR is fetched
    if [ "$subnet_cidr" == "null" ] || [ -z "$subnet_cidr" ]; then
        echo "Error: Unable to fetch CIDR block for subnet $AWS_SUBNET_ID."
        exit 1
    fi

    NETWORK=$(echo "$subnet_cidr" | cut -d/ -f1)
    NETMASK=$(echo "$subnet_cidr" | cut -d/ -f2)
    echo "Subnet CIDR network: $NETWORK"
    echo "Subnet CIDR netmask: $NETMASK"

    ip_pool_cidr="$(echo "$NETWORK" | awk -F'.' '{print $1 "." $2 "." $3 "." 192}')/26"
    echo "Creating CIDR reservation $ip_pool_cidr in subnet $AWS_SUBNET_ID..."
    aws ec2 create-subnet-cidr-reservation --subnet-id "$AWS_SUBNET_ID" --reservation-type explicit --cidr "$ip_pool_cidr"

    SUBNET_CIDR_RES_ID=$(aws ec2 get-subnet-cidr-reservations --subnet-id "$AWS_SUBNET_ID" --query 'SubnetIpv4CidrReservations[0].SubnetCidrReservationId' --output text)
    if [ "$SUBNET_CIDR_RES_ID" == "None" ]; then
        echo "Error: Failed to create subnet CIDR reservation."
        exit 1
    fi

    # Print the Subnet CIDR Reservation ID for reference
    echo "CIDR reservation created with ID: $SUBNET_CIDR_RES_ID"

    gateway=$(echo $NETWORK | awk -F'.' '{print $1 "." $2 "." $3 "." $4+1}')

    # Create IP Pool YAML file
    echo "Generating IPPool YAML..."
    cat << EOF > "$IP_POOL_YAML"
apiVersion: crd.antrea.io/v1beta1
kind: IPPool
metadata:
  name: pool1
spec:
  ipRanges:
  - cidr: $ip_pool_cidr
  subnetInfo:
    gateway: $gateway
    prefixLength: $NETMASK
EOF
    echo "Created IP Pool YAML file: $IP_POOL_YAML"
    cat $IP_POOL_YAML
    kubectl apply -f $IP_POOL_YAML

     # Create NetworkAttachmentDefinition
    kubectl apply -f "$NETATTACH_YAML"
    echo "Created NetworkAttachmentDefinition"
}

function run_test() {
     kubectl apply -f "$SRIOV_SECONDARY_NETWORKS_YAML"
     kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/sriov-network-device-plugin/refs/heads/master/deployments/sriovdp-daemonset.yaml
     kubectl get nodes -o go-template='{{range .items}}{{.metadata.name}}{{" "}}{{.status.allocatable}}{{"\n"}}{{end}}'
     kubectl apply -f https://github.com/k8snetworkplumbingwg/network-attachment-definition-client/raw/master/artifacts/networks-crd.yaml
     create_ippool_and_network_attachment_definition
     kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true
     CONTROLPLANE_NODE=$(kubectl get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].metadata.name}')
     WORKER_NODE=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[0].metadata.name}')
     kubectl label node "$CONTROLPLANE_NODE" eni-id="$CONTROLPLANE_NODE_ENI"
     kubectl label node "$WORKER_NODE" eni-id="$WORKER_NODE_ENI"

     go test -v -timeout="$TIMEOUT" antrea.io/antrea/test/e2e-secondary-network -run=TestSRIOVNetwork -provider=remote -remote.sshconfig="$SSH_CONFIG_FILE" -remote.kubeconfig="$KUBECONFIG_FILE" -deploy-antrea=false
}

function clean_up() {
    set +e
    INSTANCE_ID=$1

    echo "Retrieving all network interfaces for instance: $INSTANCE_ID"
    ENI_IDS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
        --query "Reservations[].Instances[].NetworkInterfaces[].NetworkInterfaceId" \
        --output text)

    if [ -z "$ENI_IDS" ]; then
        echo "No network interfaces found for instance: $INSTANCE_ID"
        ENI_IDS=()
    else
        echo "Found network interfaces: $ENI_IDS"
        read -ra ENI_IDS <<< "$ENI_IDS"
    fi

    echo "Terminating EC2 instance: $INSTANCE_ID"
    if ! aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"; then
        echo "Failed to terminate EC2 instance: $INSTANCE_ID"
        return 1
    fi
    echo "Successfully terminated EC2 instance: $INSTANCE_ID"

    echo "Waiting for EC2 instance to terminate..."
    if ! aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"; then
        echo "EC2 instance did not terminate successfully: $INSTANCE_ID"
        return 1
    fi
    echo "EC2 instance terminated successfully: $INSTANCE_ID"

    for ENI_ID in "${ENI_IDS[@]}"; do
        if ! aws ec2 describe-network-interfaces --network-interface-ids "$ENI_ID" &>/dev/null; then
            echo "Network interface $ENI_ID no longer exists (likely auto-deleted with instance)"
            continue
        fi

        ATTACHMENT_INFO=$(aws ec2 describe-network-interfaces \
            --network-interface-ids "$ENI_ID" \
            --query "NetworkInterfaces[0].Attachment.{AttachmentId: AttachmentId, Status: Status}" \
            --output json)

        ATTACHMENT_ID=$(echo "$ATTACHMENT_INFO" | jq -r '.AttachmentId')
        ATTACHMENT_STATUS=$(echo "$ATTACHMENT_INFO" | jq -r '.Status')

        if [[ "$ATTACHMENT_ID" != "None" && "$ATTACHMENT_STATUS" == "attached" ]]; then
            echo "Detaching network interface: $ENI_ID"
            if aws ec2 detach-network-interface --attachment-id "$ATTACHMENT_ID"; then
                echo "Successfully detached network interface: $ENI_ID"
                echo "Waiting for network interface to become available..."
                if aws ec2 wait network-interface-available --network-interface-ids "$ENI_ID"; then
                    echo "Network interface is now available: $ENI_ID"
                else
                    echo "Failed waiting for network interface availability: $ENI_ID"
                    continue
                fi
            else
                echo "Failed to detach network interface: $ENI_ID"
                continue
            fi
        fi

        echo "Deleting network interface: $ENI_ID"
        if aws ec2 delete-network-interface --network-interface-id "$ENI_ID"; then
            echo "Successfully deleted network interface: $ENI_ID"
        else
            echo "Failed to delete network interface: $ENI_ID"
        fi
    done

    set -e
}

function delete_subnet_cidr_reservation() {
      set +e
      echo "Deleting subnet cidr reservation: $SUBNET_CIDR_RES_ID"
      aws ec2 delete-subnet-cidr-reservation --subnet-cidr-reservation-id "$SUBNET_CIDR_RES_ID"
      if [ $? -eq 0 ]; then
        echo "Successfully deleted subnet cidr reservation: $SUBNET_CIDR_RES_ID"
      else
        echo "Failed to delete subnet cidr reservation: $SUBNET_CIDR_RES_ID"
      fi
      set -e
}

function clean_up_all() {
      clean_up "$CONTROLPLANE_INSTANCE_ID"
      clean_up "$WORKER_INSTANCE_ID"
      delete_subnet_cidr_reservation
}

function start_timeout_watcher() {
    local timeout_seconds=$1
    local parent_pid=$2

    local safe_timeout=$((timeout_seconds - 300))

    echo "Timeout watcher started. Will signal after ${safe_timeout} seconds."

    sleep $safe_timeout

    echo "Process timed out before AWS credential expiration! Sending termination signal to main process (PID: $parent_pid)"
    kill -SIGTERM $parent_pid 2>/dev/null || true
}

echo "===========Test SR-IOV secondary network in AWS============="

start_timeout_watcher "$AWS_DURATION_SECONDS" $$ &
timeout_watcher_pid=$!

if [[ "$RUN_SETUP_ONLY" != true ]]; then
    trap "kill -9 $timeout_watcher_pid 2>/dev/null ; clean_up_all" EXIT
else
    trap "kill -9 $timeout_watcher_pid 2>/dev/null || true" EXIT
fi

if [[ "$RUN_ALL" == true || "$RUN_SETUP_ONLY" == true ]]; then
    setup_cluster
    build_image
    upload_and_load_image "$CONTROLPLANE_IP" "$DOCKER_IMAGE_PATH"
    upload_and_load_image "$WORKER_IP" "$DOCKER_IMAGE_PATH"
    generate_ssh_config
    deploy_antrea
    run_test
fi

exit 0
