#!/usr/bin/env bash

# Copyright 2025 Antrea Authors
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

WORKDIR="/var/lib/jenkins"
SCALE_OP="auto"
JENKINS_URL="https://jenkins.antrea.io"
LABEL="antrea-kind-testbed"
ZONE="us-west1-a"
MACHINE_TYPE="e2-standard-4"
IMAGE_FAMILY="ubuntu-2404-lts-amd64"
IMAGE_PROJECT="ubuntu-os-cloud"
BOOT_DISK_SIZE="100GB"
BOOT_DISK_TYPE="pd-ssd"
AGENT_NAME_PATTERN="jenkins-agent"
SWARM_CLIENT_JAR="swarm-client.jar"
NEW_AGENT_NAME="$AGENT_NAME_PATTERN-$(date +%Y-%m-%d-%H-%M-%S)"
MAX_AGENTS=10
JOB_EXISTS=0
KIND_VERSION=$(head -n1 ./ci/kind/version)
JOB_COUNT=0

_usage="Usage: $0 [--workdir <JenkinsPath>] [--setup-only] [--cleanup-only] [--jenkins-url <Url>]  [--jenkins-user <User>] [--jenkins-token <Token>] [--gke-project <Project>] [--gke-network <Network>] [--gke-subnet <Subnet>] [--label <Label>] [--max-agents <Number>]

Scale jenkins agents to run CI tests.

        --workdir                Home path for Jenkins during agent setup. Default is $WORKDIR.
        --scale-op               Specify scaling mode: auto (default, setup + cleanup), up (setup only), down (cleanup only).
        --jenkins-url            Jenkins url.
        --jenkins-user           Jenkins user name.
        --jenkins-token          Jenkins API token.
        --gke-project            The GKE project to be used.
        --gke-network            The GKE network to be used.
        --gke-subnet             The GKE subnet to be used.
        --label                  Label for the jenkins agent.
        --max-agents             Maximum number of agents allowed. Default is $MAX_AGENTS"

function print_usage {
    echoerr "$_usage"
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --workdir)
    WORKDIR="$2"
    shift 2
    ;;
    --scale-op)
    SCALE_OP="$2"
    if [[ ! "$SCALE_OP" =~ ^(auto|up|down)$ ]]; then
        echo "Error: Invalid value for --scale-op. Expected one of: auto, up, down."
        exit 1
    fi
    shift
    ;;
    --jenkins-url)
    JENKINS_URL="$2"
    shift 2
    ;;
    --jenkins-user)
    JENKINS_USER="$2"
    shift 2
    ;;
    --jenkins-token)
    JENKINS_API_TOKEN="$2"
    shift 2 
    ;;
    --gke-project)
    GKE_PROJECT="$2"
    shift 2 
    ;;
    --gke-network)
    GKE_NETWORK="$2"
    shift 2
    ;;
    --gke-subnet)
    GKE_SUBNET="$2"
    shift 2
    ;;
    --max-agents)
    MAX_AGENTS="$2"
    shift 2
    ;;
    --label)
    LABEL="$2"
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

if [ -z "$GKE_PROJECT" ] || [ -z "$GKE_NETWORK" ]; then
    echoerr "Both --gke-project and --gke-network must be specified."
    exit 1
fi

# disable gcloud prompts, e.g., when deleting resources
export CLOUDSDK_CORE_DISABLE_PROMPTS=1
export CLOUDSDK_CORE_PROJECT="$GKE_PROJECT"

function check_jobs_in_queue {
    local LABEL=$1

    for i in {1..2}; do
        QUEUE_JOBS=$(curl -k -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/queue/api/json")
        echo $QUEUE_JOBS
        JOB_COUNT=$(echo "$QUEUE_JOBS" | jq --arg label "$LABEL" '[.items[] | select(.why|test("Waiting for next available executor") and contains($label))] | length')

        if [ "$JOB_COUNT" -gt 0 ]; then
            echo "Job with label $LABEL found in queue"
            JOB_EXISTS=1
            echo "Wait 10 seconds to retry to ensure it's still in queue before creating a new agent..."
            sleep 10
        else
            echo "No job with label $LABEL found in queue. Exit."
            JOB_EXISTS=0
            break
        fi
    done
}

function add_agent {
    echo "Checking if there are jobs in the Jenkins queue with label: $LABEL"
    check_jobs_in_queue $LABEL
    echo $JOB_EXISTS

    if [ "$JOB_EXISTS" -ne 1 ]; then
        echo "Jobs with label $LABEL not found in the queue. Exit."
        return
    fi

    echo "Checking current number of agents matching pattern $AGENT_NAME_PATTERN"
    CURRENT_AGENT_COUNT=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/computer/api/json" \
        | jq -r '.computer[].displayName' | grep -c "$AGENT_NAME_PATTERN" || true)
    echo $CURRENT_AGENT_COUNT
    if [ "$CURRENT_AGENT_COUNT" -ge "$MAX_AGENTS" ]; then
        echo "Agent count ($CURRENT_AGENT_COUNT) has reached the limit ($MAX_AGENTS). No new agent will be added."
        return
    fi

    echo "Jobs with label $LABEL exist in the queue. Proceeding with agent creation..."
    sudo gcloud compute instances create "$NEW_AGENT_NAME" --zone="$ZONE" --machine-type="$MACHINE_TYPE" --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" --boot-disk-size="$BOOT_DISK_SIZE" --boot-disk-type="$BOOT_DISK_TYPE" \
        --network ${GKE_NETWORK} --subnet ${GKE_SUBNET}
    if [ $? -ne 0 ]; then
        echoerr "Failed to create VM instance $NEW_AGENT_NAME."
        return 1
    fi

    echo "Waiting for External IP of $NEW_AGENT_NAME to be available..."
    IP_READY=false
    for i in {1..18}; do
        external_ip=$(gcloud compute instances describe "$NEW_AGENT_NAME" --zone="$ZONE" --format='get(networkInterfaces[0].networkIP)')
        if [ -n "$external_ip" ]; then
            echo "External IP $external_ip is now available."
            if gcloud compute ssh ubuntu@"$NEW_AGENT_NAME" --zone "$ZONE" --internal-ip --command "echo ready" --quiet --ssh-flag="-o ConnectTimeout=5" &>/dev/null; then
                echo "VM is accessible over SSH."
                IP_READY=true
                break
            else
                echo "SSH not ready yet. Waiting 10 seconds..."
                sleep 10
            fi
        else
            echo "External IP not ready yet. Waiting 10 seconds..."
            sleep 10
        fi
    done

    if [ "$IP_READY" = false ]; then
        echo "External IP for $NEW_AGENT_NAME did not become ready within 3 minutes. Exiting..."
        sudo gcloud compute instances delete "$NEW_AGENT_NAME" --zone="$ZONE" --quiet
        return 1
    fi

    SETUP_COMMAND="
    # Download Kind
    curl -Lo ./kind https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-linux-amd64;
    chmod +x ./kind;
    sudo mv kind /usr/local/bin;

    # Install Docker
    sudo apt-get update;
    sudo apt-get install -y ca-certificates curl;
    sudo install -m 0755 -d /etc/apt/keyrings;
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc;
    sudo chmod a+r /etc/apt/keyrings/docker.asc;
    echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \$(. /etc/os-release && echo \"\${UBUNTU_CODENAME:-\$VERSION_CODENAME}\") stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null;
    sudo apt-get update;
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin;
    sudo usermod -aG docker ubuntu;

    # Install Utils
    sudo snap install kubectl --classic;
    sudo apt install -y make;
    wget https://repo.jenkins-ci.org/releases/org/jenkins-ci/plugins/swarm-client/3.43/swarm-client-3.43.jar -O swarm-client.jar;
    sudo apt-get install openjdk-17-jdk -y;

    # Create work directory if it doesn't exist
    sudo mkdir -p $WORKDIR;
    sudo chown ubuntu:ubuntu $WORKDIR;"

    JOIN_COMMAND="
    # Start the Jenkins Agent
    java -jar $SWARM_CLIENT_JAR -master $JENKINS_URL -username $JENKINS_USER -password $JENKINS_API_TOKEN \
        -name $NEW_AGENT_NAME -labels $LABEL -executors 1 -retry 3 -mode exclusive -disableSslVerification -deleteExistingClients -workDir $WORKDIR -webSocket > jenkins_swarm.log 2>&1 &"

    # Run from agent command line
    set +e
    gcloud compute ssh ubuntu@"$NEW_AGENT_NAME" --internal-ip --zone="$ZONE" --command "$SETUP_COMMAND"
    gcloud compute ssh ubuntu@"$NEW_AGENT_NAME" --internal-ip --zone="$ZONE" --command "$JOIN_COMMAND"
    rc=$?
    set -e
    if [ "$rc" != 0 ]; then
      sudo gcloud compute instances delete "$NEW_AGENT_NAME" --zone="$ZONE" --quiet
      return 1
    fi
    sleep 5
    
    echo "Agent $NEW_AGENT_NAME has been added."
}

function is_idle {
  local agent_name="$1"
  curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
    "$JENKINS_URL/computer/$agent_name/api/json?tree=idle" \
  | jq -e '.idle == true' >/dev/null
}

function remove_idle_agents {
    AGENT_LIST=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/computer/api/json" | jq -r '.computer[] | .displayName')

    if [ -z "$AGENT_LIST" ]; then
        echoerr "No agents found."
        return
    fi
    
    for AGENT_NAME in $AGENT_LIST; do
        if [[ "$AGENT_NAME" == *"$AGENT_NAME_PATTERN"* ]]; then
            echo "Checking Agent: $AGENT_NAME"

            if is_idle "$AGENT_NAME"; then
                echo "Agent $AGENT_NAME can be safely removed"

                echo "Bring agent $AGENT_NAME offline"
                curl -X POST "$JENKINS_URL/computer/$AGENT_NAME/toggleOffline" --data-urlencode "offlineMessage=remove agent" --user "$JENKINS_USER:$JENKINS_API_TOKEN"

                # Recheck if there are no running jobs
                if is_idle "$AGENT_NAME"; then
                    # Remove agent by calling jenkins api
                    curl -X POST "$JENKINS_URL/computer/$AGENT_NAME/doDelete" --user "$JENKINS_USER:$JENKINS_API_TOKEN"
            
                    # destroy the cloud VM
                    baseAgentName=${AGENT_NAME%-*}
                    sudo gcloud compute instances delete "$baseAgentName" --zone="$ZONE" --quiet
                    echo "Agent $AGENT_NAME has been deleted."
                    break
                else
                    echo "Agent $AGENT_NAME still has jobs running, cannot be deleted."
                fi
            else 
                echo "Agent $AGENT_NAME still has jobs running, cannot be deleted."
            fi
        fi
    done

}

case $SCALE_OP in
  auto)
    echo "Running in auto scale mode — script decides whether to scale up or down."
    # In auto mode, after adding an agent, a deletion check is performed. The agent will be removed only if
    # no jobs are running on it, ensuring safe removal.
    add_agent
    remove_idle_agents
    ;;
  up)
    echo "Scaling up agents..."
    add_agent
    ;;
  down)
    echo "Scaling down agents..."
    remove_idle_agents
    ;;
esac
