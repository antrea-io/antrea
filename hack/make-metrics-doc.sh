#!/usr/bin/env bash

# Copyright 2020 Antrea Authors
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

# The script deploys a Kind cluster with Prometheus metrics enabled. Then queries Antrea endpoints for metrics, and
# outputs it to the console.
# When a doc filename parameter is specified, the script updates the metrics list within the document with the metrics
# from the Kind deployment.

function exit_handler() {
    echo "Cleaning up..."
    if [ -f $certfile ]; then
        rm -rf certfile
        $THIS_DIR/../ci/kind/kind-setup.sh destroy kind
    fi
}

trap exit_handler INT EXIT

function get_metrics_url() {
        pod_name=$1
        host_ip=$(kubectl get pod -n kube-system $pod_name -o jsonpath="{.status.hostIP}")
        host_port=$(kubectl get pod -n kube-system $pod_name -o jsonpath="{.spec.containers[*].ports[*].hostPort}")

        echo "https://$host_ip:$host_port/metrics"
}

function format_metrics() {
        sorted_metrics=$1
        # Gather list of metric names
        metrics_types_unarranged=$(awk '/# TYPE/{print $3}' <<< $sorted_metrics)
        # Put Antrea-specific metrics at the beginning, push 3rd parties after
        metrics_types=$(grep antrea <<< $metrics_types_unarranged)$'\n'$(grep -v antrea <<< $metrics_types_unarranged)
        # Gather metrics descriptions
        metrics_help=$(grep '# HELP' <<< $sorted_metrics | sed 's/\[.*\] //i')
        last_pfx=""
        echo 'Below is a list of metrics, provided by the components and by 3rd parties.'
        echo
        echo "### Antrea Metrics"
        for metric in $metrics_types; do
                metric_pfx=$(sed 's/_/ /g' <<< $metric | awk '{print $1}')
                if [ "$metric_pfx" == 'antrea' ]; then
                        # For Antrea metrics, add Agent, Controller to title
                        metric_pfx=$(sed 's/_/ /g' <<< $metric | awk '{print $1" "$2}')
                fi
                if [ "$last_pfx" != "$metric_pfx" ]; then
                        echo
                        # Ouptut metrics title
                        # Ouptut 3rd party metrics title
                        if [[ "$last_pfx" =~ ^antrea.* ]] && [[ ! "$metric_pfx" =~ ^antrea.* ]]; then
                                echo "### Common Metrics Provided by Infrastructure"
                                echo
                        fi
                        # Ouptut metrics title
                        echo "#### "$(sed -e "s/\b\(.\)/\u\1/g" <<< $metric_pfx)" Metrics"
                        echo
                        last_pfx=$metric_pfx
                fi
                metric_help=$(grep " $metric " <<< $metrics_help | sed "s/.*$metric //")
                echo "- **$metric:** $metric_help"
        done
}

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
        echo 'Usage: make-metrics-doc.sh [-h|--help|<metrics_document>]'
        exit 0
fi
metrics_doc=$1
if [ "$metrics_doc" != "" ] && [ ! -f $metrics_doc ]; then
        echo "Metrics document not found at $metrics_doc"
        exit 1
fi

set -eo pipefail
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Initialize a Kind Antrea cluster
$THIS_DIR/../ci/kind/kind-setup.sh create kind --prometheus --num-workers 0

# Wait for Antrea components to be ready, allow Antrea inits to complete
kubectl -n kube-system wait --for=condition=ready --timeout=120s pod -l app=antrea
sleep 30

# Extract Antrea credentials
certfile=$(mktemp /tmp/cacert.XXXXXX.ca)
secret_name=$(kubectl get serviceaccounts -n monitoring prometheus -o jsonpath="{.secrets[*].name}")
kubectl get secrets -n monitoring $secret_name -o jsonpath="{.data.ca\.crt}" | base64 -d > $certfile
token=$(kubectl get secrets -n monitoring $secret_name --template "{{.data.token}}" | base64 -d)

# Find agent, controller pods
controller_pod=$(kubectl get pod -n kube-system | awk '/antrea-controller/{print $1}')
agent_pod=$(kubectl get pod -n kube-system | awk '/antrea-agent/{print $1}' | head -n1)

agent_metrics_url=$(get_metrics_url $agent_pod)
controller_metrics_url=$(get_metrics_url $controller_pod)

# Retrieve agent and controller metrics
agent_metrics=$(curl -fsk -H "Authorization: Bearer $token" --cacert $certfile $agent_metrics_url | grep '^#')
controller_metrics=$(curl -fsk -H "Authorization: Bearer $token" --cacert $certfile $controller_metrics_url | grep '^#')

# Sort metrics, eliminate duplicates e.g apiserver etc
sorted_metrics=$(sort -u <<< "${agent_metrics}"$'\n'"${controller_metrics}")

# Format metrics
formatted_metrics=$(format_metrics "$sorted_metrics")

if [ "$metrics_doc" == "" ]; then
        fmt -w 80 -s <<< $formatted_metrics
else
        sed -i '/^Below is a list of metrics, provided by the components and by 3rd parties.$/,$d' $metrics_doc
        fmt -w 80 -s <<< $formatted_metrics >> $metrics_doc
fi
