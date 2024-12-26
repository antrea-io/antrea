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
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
JENKINS_URL="https://jenkins.antrea.io"
LABEL="antrea-kind-testbed"
ZONE="us-west1-a"
MACHINE_TYPE="e2-standard-4"
IMAGE_FAMILY="ubuntu-2204"
IMAGE_PROJECT="ubuntu-os-cloud"
BOOT_DISK_SIZE="200GB"
AGENT_NAME_PATTERN="jenkins-agent"
SWARM_CLIENT_JAR="swarm-client.jar"
NEW_AGENT_NAME="$AGENT_NAME_PATTERN-$(date +%Y-%m-%d-%H-%M-%S)"
MAX_AGENTS=10

_usage="Usage: $0 [--workdir <JenkinsPath>] [--setup-only] [--cleanup-only] [--kind]  [--jenkins-user <User>] [--jenkins-token <Token>] [--gke-project <Project>]  [--label <Label>] [--max-agents <Number>]

Scale a jenkins agent to run CI tests.

        --workdir                Home path for Jenkins during agent setup. Default is $WORKDIR.
        --setup-only             Only perform setting up the agent.
        --cleanup-only           Only perform cleaning up the agent.
        --jenkins-user           Jenkins user name.
        --jenkins-token          Jenkins API token.
        --gke-project            The GKE project to be used.
        --label                  Label for the jenkins agent.
        --max-agents             Maximum number of agents allowed. Default is $MAX_AGENTS
        --kind                   Setup kind testbed."

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
    --workdir)
    WORKDIR="$2"
    shift 2
    ;;
    --setup-only)
    RUN_SETUP_ONLY=true
    shift
    ;;
    --cleanup-only)
    RUN_CLEANUP_ONLY=true
    shift
    ;;
    --kind)
    KIND=true
    shift
    ;;
    --jenkins-user)
    JENKINS_USER="$2"
    shift 2
    ;;
    --jenkins-token)
    JENKINS_TOKEN="$2"
    shift 2 
    ;;
    --gke-project)
    GKE_PROJECT="$2"
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

# disable gcloud prompts, e.g., when deleting resources
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

export CLOUDSDK_CORE_PROJECT="$GKE_PROJECT"

function check_jobs_in_queue {
    local LABEL=$1
    local SUCCESS=0

    for i in {1..2}; do
        QUEUE_JOBS=$(curl -k -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/queue/api/json")

        JOB_FOUND=$(echo "$QUEUE_JOBS" | jq -r '.items[] | select(.task.labels != null) | .task.labels[]' | grep -w "$LABEL")

        if [ -n "$JOB_FOUND" ]; then
            echo "Job with label $LABEL found in queue. Retrying in 10 seconds..."
            SUCCESS=1
            sleep 10
        else
            echo "No job with label $LABEL found in queue. Exit."
            SUCCESS=0
            break
        fi
    done

    echo $SUCCESS
}

function add_agent {
    echo "Checking if there are jobs in the Jenkins queue with label: $LABEL"
    JOB_EXISTS=$(check_jobs_in_queue "$LABEL")

    if [ "$JOB_EXISTS" -ne 0 ]; then
        echo "Jobs with label $LABEL not found in the queue. Exit."
        return 1
    fi

    echo "Checking current number of agents matching pattern $AGENT_NAME_PATTERN"
    CURRENT_AGENT_COUNT=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/computer/api/json" \
        | jq -r '.computer[].displayName' | grep -c "$AGENT_NAME_PATTERN")

    if [ "$CURRENT_AGENT_COUNT" -ge "$MAX_AGENTS" ]; then
        echo "Agent count ($CURRENT_AGENT_COUNT) has reached the limit ($MAX_AGENTS). No new agent will be added."
        return 1
    fi

    echo "Jobs with label $LABEL exist in the queue. Proceeding with agent creation..."
    sudo gcloud compute instances create "$NEW_AGENT_NAME" --zone="$ZONE" --machine-type="$MACHINE_TYPE" --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" --boot-disk-size="$BOOT_DISK_SIZE"
    if [ $? -ne 0 ]; then
        echoerr "Failed to create VM instance $NEW_AGENT_NAME."
        return 1
    fi

    echo "Waiting for External IP of $NEW_AGENT_NAME to be available..."
    IP_READY=false
    for i in {1..18}; do
        external_ip=$(gcloud compute instances describe "$NEW_AGENT_NAME" --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
        
        if [ -n "$external_ip" ]; then
            echo "External IP $external_ip is now available."
            IP_READY=true
            break
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


    JOIN_COMMAND="java -jar $SWARM_CLIENT_JAR -master $JENKINS_URL -username $JENKINS_USER -password $JENKINS_API_TOKEN \
        -name $NEW_AGENT_NAME -labels $LABEL -executors 1 -retry 3 -mode exclusive -disableSslVerification -deleteExistingClients -workDir $WORKDIR &"

    # Run from agent command line
    set +e
    gcloud compute ssh "$NEW_AGENT_NAME" --zone="$ZONE" --command \
        "wget https://repo.jenkins-ci.org/releases/org/jenkins-ci/plugins/swarm-client/3.43/swarm-client-3.43.jar -O swarm-client.jar && sudo apt-get install openjdk-11-jdk -y && $JOIN_COMMAND"
    rc=$?
    set -e
    if [ "$rc" != 0 ]; then
      sudo gcloud compute instances delete "$NEW_AGENT_NAME" --zone="$ZONE" --quiet
      return 1
    fi
    
    echo "Agent $NEW_AGENT_NAME has been added."
}

function remove_agent {
    AGENT_LIST=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/computer/api/json" | jq -r '.computer[] | .displayName')

    if [ -z "$AGENT_LIST" ]; then
        echoerr "No agents found."
        return 1
    fi
    
    DELETED_ONCE=false
    for AGENT_NAME in $AGENT_LIST; do
        if [[ "$AGENT_NAME" == *"$AGENT_NAME_PATTERN"* ]]; then
            echo "Checking Agent: $AGENT_NAME"

            RUNNING_JOBS=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/computer/$AGENT_NAME/api/json" | jq '[.executors[] | select(.currentExecutable != null)] | length')

            if [ "$RUNNING_JOBS" -eq 0 ]; then
                echo "Agent $AGENT_NAME can be safely removed"

                echo "Removing label from agent $AGENT_NAME"
                curl -X POST "$JENKINS_URL/computer/$AGENT_NAME/label" --user "$JENKINS_USER:$JENKINS_API_TOKEN" -d "labels="

                # Recheck if there are no running jobs
                RUNNING_JOBS=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/computer/$AGENT_NAME/api/json" | jq '[.executors[] | select(.currentExecutable != null)] | length')
            
                if [ "$RUNNING_JOBS" -eq 0 ]; then
                    # Remove agent by calling jenkins api
                    curl -X POST "$JENKINS_URL/computer/doDelete?name=$AGENT_NAME" --user "$JENKINS_USER:$JENKINS_API_TOKEN"
            
                    # destroy the cloud VM
                    sudo gcloud compute instances delete "$AGENT_NAME" --zone="$ZONE" --quiet
                    echo "Agent $AGENT_NAME has been deleted."
                    DELETED_ONCE=true
                    break
                else
                    echo "Agent $AGENT_NAME still has $RUNNING_JOBS jobs running, cannot be deleted."
                fi
            else 
                echo "Agent $AGENT_NAME is running $RUNNING_JOBS jobs, cannot be deleted."
            fi
        fi
    done

    if [ "$DELETED_ONCE" = false ]; then
        echo "No agents can be removed."
    fi
}

if [[ "$RUN_SETUP_ONLY" == true ]]; then
    add_agent
    exit 0
fi

if [[ "$RUN_CLEANUP_ONLY" == true ]]; then
    remove_agent
    exit 0
fi

add_agent
remove_agent
