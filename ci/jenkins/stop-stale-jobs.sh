#!/usr/bin/env bash

# Copyright 2023 Antrea Authors
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

PULL_REQUEST_ID=""
JENKINS_URL=""
DEFAULT_WORKDIR=$HOME

_usage="Usage: $0 [--pull-request <PullRequestId>] [--jenkins <JenkinsURL>]

        --pull-request           Unique Pull Request id, to verify the stale jobs that need to be aborted.
        --jenkins                Jenkins url to fetch the information about jobs."

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
    --pull-request)
    PULL_REQUEST_ID="$2"
    shift 2
    ;;
    --jenkins)
    JENKINS_URL="$2"
    shift 2
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *) 
    echoerr "Unknown option $1"
    exit 1
    ;;
esac
done

function abort_queue_jobs {
    echo "====== Checking for capv stale waiting jobs on PR ${PULL_REQUEST_ID} ======"
    echo "${JENKINS_URL}"
    queue="$(curl -s -XGET "${JENKINS_URL}queue/api/json" )"
    length_of_queue="$(echo "$queue" | jq '[.[]][2]' | jq length)"

    for (( j=0; j<$length_of_queue; j++ )); do
            # Fetch the waiting job id and its pr id.
            waiting_job_pr_id=$(echo "$queue" | jq -r "[.[]][2][$j].actions[1].parameters[9].value")
            job_name=$(echo "$queue" | jq -r "[.[]][2][$j].task.name")

            if [[ "$PULL_REQUEST_ID" == "$waiting_job_pr_id" ]]; then
                echo "====== Abort waiting job $job_name on PR ${PULL_REQUEST_ID} ======"
                job_id=$(echo "$queue" | jq "[.[]][2][$j].id")
                CURL_RETURN_CODE=0
                curl -XPOST "${JENKINS_URL}queue/cancelItem?id=$job_id" -u admin:$JENKINS_API_TOKEN || CURL_RETURN_CODE=$? || true
                if [[ ${CURL_RETURN_CODE} -ne 0 ]]; then  
                     echo "Curl connection failed with return code - ${CURL_RETURN_CODE}"
                     exit 1
                fi

            fi
    done
}

function abort_running_jobs {
    echo "====== Checking for capv stale running jobs on PR ${PULL_REQUEST_ID} ======"
    capv_jobs="$(curl -s -XGET "${JENKINS_URL}label/antrea-test-node/api/json")"
    length_of_capv_jobs=$(echo "$capv_jobs" | jq "[.[]][10]" | jq length)

    for ((i=0; i<$length_of_capv_jobs; i++)); do
    
        capv_job_name=$(echo "$capv_jobs" | jq -r "[.[]][10][$i].name")

        # Job color is the status of the jobs, for example if jobs are in running state then its value will be {"red_anime","blue_anime","aborted_anime".....}
        # so here "*_anime" means job is in running state.
        # red_anime: last failed job is in running state.
        # blue_anime: last successful job is in running state.
        # aborted_anime: last aborted job is in running state.   
        job_color=$(echo "$capv_jobs" | jq -r "[.[]][10][$i].color")

        if [[ ${job_color: -5} == "anime" ]]; then
            last_build_number=$(curl -s -XGET "${JENKINS_URL}job/$capv_job_name/api/json" | jq -r "[.[]][10][0].number")
            jenkins_variable="$(curl -s -XGET "${JENKINS_URL}job/"$capv_job_name"/"$last_build_number"/injectedEnvVars/api/json")"
            pr_id=$(echo "$jenkins_variable" | jq -r "[.[]][1].ghprbPullId")

            if [[ "$PULL_REQUEST_ID" == "$pr_id" ]]; then
                echo "====== Abort running job $capv_job_name with build ID $last_build_number on PR ${PULL_REQUEST_ID} ======"

                # Need to stop first then clean.
                curl -XPOST "${JENKINS_URL}job/$capv_job_name/$last_build_number/stop" -u admin:$JENKINS_API_TOKEN || true
                
                # Ensures that the job has been aborted before cleanup.
                max_retries=5
                job_aborted=false
                while [[ "${max_retries}" -gt 0 ]]; do
                    status=$(curl -s -XGET "${JENKINS_URL}job/$capv_job_name/$last_build_number/api/json" | jq -r "[.[]][14]")
                    if [[ "$status" == "ABORTED" ]]; then
                         job_aborted=true
                         break
                    fi
                    sleep 5
                    max_retries=$((max_retries-1)) 
                done
                if [[ $job_aborted == true ]]; then

                    CLUSTER_NAME=$(echo "$jenkins_variable" | jq -r "[.[]][1].BUILD_TAG")
                    ip_of_capv_testbed=$(echo "$jenkins_variable" | jq "[.[]][1].SSH_CONNECTION" | awk '{print $3}')

                    cleanup_running_job "$CLUSTER_NAME" "$ip_of_capv_testbed"
                else
                    echo "Job $capv_job_name still running on PR ${PULL_REQUEST_ID}"
                fi
            fi
        fi   
    done
}

function stop_all() {
     # Abort all stale waiting jobs on PR.
      abort_queue_jobs

     # Abort all stale running jobs on PR.
      abort_running_jobs   
}

function release_static_ip {
    CLUSTER_NAME=$1
    ip_of_capv_testbed=$2
    echo "=== Releasing IP ==="
    ssh -o StrictHostKeyChecking=no -i /var/lib/jenkins/.ssh/id_rsa -n jenkins@${ip_of_capv_testbed} \
    "cat \"$DEFAULT_WORKDIR/host-local.json\" | \
    CNI_COMMAND=DEL CNI_CONTAINERID=\"$CLUSTER_NAME\" \
    CNI_NETNS=/dev/null CNI_IFNAME=dummy0 CNI_PATH=. /usr/bin/host-local"

    if [[ $? -eq 0 ]]; then
       echo "IP Release Successful for: ${ip_of_capv_testbed}"
    else
       echo "IP Release Failed for: ${ip_of_capv_testbed}"
       exit 1
    fi
}

function cleanup_running_job {
    CLUSTER_NAME=$1
    ip_of_capv_testbed=$2
    echo "=== Cleaning up VMC cluster ${CLUSTER_NAME} ==="
    # To run kubectl cmds.
    ssh -o StrictHostKeyChecking=no -i /var/lib/jenkins/.ssh/id_rsa -n jenkins@${ip_of_capv_testbed} kubectl delete cluster ${CLUSTER_NAME} -n ${CLUSTER_NAME}
    if [[ $? -ne 0 ]]; then
        echo "Failed to delete cluster $CLUSTER_NAME"
        exit 1
    fi

    ssh -o StrictHostKeyChecking=no -i /var/lib/jenkins/.ssh/id_rsa -n jenkins@${ip_of_capv_testbed} kubectl delete ns ${CLUSTER_NAME}
    if [[ $? -ne 0 ]]; then
        echo "Failed to delete cluster ns $CLUSTER_NAME"
        exit 1
    fi

    echo "=== Cluster ${CLUSTER_NAME} cleanup succeeded ==="
    release_static_ip "$CLUSTER_NAME" "$ip_of_capv_testbed"
}

stop_all
