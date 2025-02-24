#!/usr/bin/env bash

# Copyright 2024 Antrea Authors
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
LABEL="kind"
ZONE="us-west1-a"
MACHINE_TYPE="e2-standard-4"
IMAGE_FAMILY="ubuntu-2204-lts"
IMAGE_PROJECT="ubuntu-os-cloud"
BOOT_DISK_SIZE="200GB"
AGENT_NAME_PATTERN="jenkins-agent"
NEW_AGENT_NAME="$AGENT_NAME_PATTERN-$(date +%s)"

_usage="Usage: $0 [--workdir <HomePath>] [--setup-only] [--cleanup-only] [--kind]

Scale a jenkins agent to run CI tests.

        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --setup-only             Only perform setting up the cluster and run test.
        --cleanup-only           Only perform cleaning up the cluster.
        --jenkins-user           Jenkins user name.
        --jenkins-token          Jenkins API token.
        --label                  Label for the jenkins agent.
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
        return 1
    fi


    cat <<EOF >> node.json
{
   "name": "$NEW_AGENT_NAME",
   "nodeDescription": "$NEW_AGENT_NAME",
   "numExecutors": "5",
   "remoteFS": "$WORKDIR",
   "labelString": "$LABEL",
   "mode": "EXCLUSIVE",
   "": [
      "hudson.slaves.JNLPLauncher",
      "hudson.slaves.RetentionStrategy$Always"
   ],
   "launcher": {
      "stapler-class": "hudson.slaves.JNLPLauncher",
      "$class": "hudson.slaves.JNLPLauncher",
      "workDirSettings": {
         "disabled": true,
         "workDirPath": "",
         "internalDir": "remoting",
         "failIfWorkDirIsMissing": false
      },
      "tunnel": "",
      "vmargs": ""
   },
   "retentionStrategy": {
      "stapler-class": "hudson.slaves.RetentionStrategy$Always",
      "$class": "hudson.slaves.RetentionStrategy$Always"
   },
   "nodeProperties": {
      "stapler-class-bag": "true",
      "hudson-slaves-EnvironmentVariablesNodeProperty": {
         "env": [
            {
               "key": "JAVA_HOME",
               "value": "/usr/lib/jvm/java-11-openjdk-amd64"
            }
         ]
      },
      "_comment:": {
         "hudson-tools-ToolLocationNodeProperty": {
           "locations": [
               {
                  "key": "hudson.model.JDK$DescriptorImpl@JAVA-11",
                  "home": "/usr/bin/java"
               }
            ]
         }
      }
   }
}
EOF
    
    response_code=$(curl -L -s -k -v -w "%{http_code}" -u $JENKINS_USER:$JENKINS_API_TOKEN -H "Content-Type:application/x-www-form-urlencoded" -X POST \
        -d "json=$(cat node.json)" "$JENKINS_URL/computer/doCreateItem?name=$NEW_AGENT_NAME&type=hudson.slaves.DumbSlave")
    if [[ "$response_code" -ne 200 ]]; then
        echoerr "Failed to create agent. HTTP status code: $response_code"
        return 1
    fi

    jnlp_url="$JENKINS_USER/computer/$NEW_AGENT_NAME/slave-agent.jnlp"
    curl -k -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$jnlp_url" -o agent.jnlp
    secret=$(grep -oP '(?<=<argument>)[^<]+' agent.jnlp | head -1)

    # Run from agent command line
    gcloud compute ssh "$NEW_AGENT_NAME" --zone="$ZONE" --command \
        "curl -ksO $JENKINS_URL/jnlpJars/agent.jar && java -jar agent.jar -url $JENKINS_URL -secret $secret -name $NEW_AGENT_NAME"
    
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
            
                    # destory the cloud VM
                    sudo gcloud compute instances delete "$AGENT_NAME" --zone="$ZONE" --quiet
                    echo "Agent $AGENT_NAME has been deleted。"
                    DELETED_ONCE=true
                    break
                else
                    echo "Agent $AGENT_NAME still has $RUNNING_JOBS jobs running, cannot delete."
                fi
            else 
                echo "Agent $AGENT_NAME is running $RUNNING_JOBS jobs, cannot delete."
            fi
        fi
    done

    if [ "$DELETED_ONCE" = false ]; then
        echo "No agents can be removed."
    fi
}

if [[ "$RUN_SETUP_ONLY" != true ]]; then
    remove_agent
    exit 0
fi

if [[ "$RUN_CLEANUP_ONLY" != true ]]; then
    add_agent
    exit 0
fi