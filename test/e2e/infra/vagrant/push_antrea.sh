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


function usage() {
    echo "Usage: push_antrea.sh [--prometheus] [-fc|--flow-collector <Address>] [-fa|--flow-aggregator] [-h|--help]
    Push the latest Antrea image to all vagrant nodes and restart the Antrea daemons
          --prometheus                 Deploy Prometheus service to scrape metrics
                                       from Antrea Agents and Controllers.
          --flow-collector <Addr|ELK|Grafana>
                                       Provide either the external IPFIX collector
                                       address or specify 'ELK' to deploy the ELK
                                       flow collector or specify 'Grafana' to deploy the Grafana flow collector.
                                       The address should be given in the format IP:port:proto. Example: 192.168.1.100:4739:udp.
                                       Please note that with this option we deploy
                                       the Flow Aggregator Service.
          --flow-aggregator            Upload Flow Aggregator image and manifests
                                       onto the Vagrant nodes to run Flow Aggregator e2e tests."
}

# Process execution flags
RUN_PROMETHEUS=false
FLOW_COLLECTOR=""
FLOW_AGGREGATOR=false

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --prometheus)
    RUN_PROMETHEUS=true
    shift
    ;;
    -fc|--flow-collector)
    FLOW_COLLECTOR="$2"
    FLOW_AGGREGATOR=true
    shift 2
    ;;
    -fa|--flow-aggregator)
    FLOW_AGGREGATOR=true
    shift 1
    ;;
    -h|--help)
    usage
    exit 0
    ;;
    *)
    usage
    exit 1
esac
done

SAVED_ANTREA_IMG=/tmp/antrea-ubuntu.tar
ANTREA_IMG_NAME=projects.registry.vmware.com/antrea/antrea-ubuntu:latest

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR

ANTREA_BASE_YML=$THIS_DIR/../../../../build/yamls/antrea.yml
ANTREA_IPSEC_YML=$THIS_DIR/../../../../build/yamls/antrea-ipsec.yml
ANTREA_PROMETHEUS_YML=$THIS_DIR/../../../../build/yamls/antrea-prometheus.yml

ANTREA_YML="/tmp/antrea.yml"

cp "${ANTREA_BASE_YML}" "${ANTREA_YML}"

if [ "$RUN_PROMETHEUS" == "true" ]; then
    # Prepare Antrea yamls
    echo "---" >> "${ANTREA_YML}"
    cat "${ANTREA_PROMETHEUS_YML}" >> "${ANTREA_YML}"
fi

if [ ! -f ssh-config ]; then
    echo "File ssh-config does not exist in current directory"
    echo "Did you run ./provision.sh?"
    exit 1
fi

# Read all hosts in ssh-config file
HOST_PATTERN="Host (k8s-node-.*)"
ALL_HOSTS=()
while IFS= read -r line; do
    if [[ $line =~ $HOST_PATTERN ]]; then
        ALL_HOSTS+=( "${BASH_REMATCH[1]}" )
    fi
done < ssh-config

function waitForNodes {
    pids=("$@")
    for pid in "${pids[@]}"; do
        if ! wait $pid; then
            echo "Command failed for one or more node"
            wait # wait for all remaining processes
            exit 2
        fi
    done
}

function pushImgToNodes() {
    IMG_NAME=$1
    SAVED_IMG=$2

    docker inspect $IMG_NAME > /dev/null
    if [ $? -ne 0 ]; then
        echo "Docker image $IMG_NAME was not found"
        exit 1
    fi

    echo "Saving $IMG_NAME image to $SAVED_IMG"
    docker save -o $SAVED_IMG $IMG_NAME

    echo "Copying $IMG_NAME image to every node..."
    pids=()
    for name in "${ALL_HOSTS[@]}"; do
        scp -F ssh-config $SAVED_IMG $name:/tmp/image.tar &
        pids+=($!)
    done
    # Wait for all child processes to complete
    waitForNodes "${pids[@]}"
    echo "Done!"

    echo "Loading $IMG_NAME image in every node..."
    pids=()
    for name in "${ALL_HOSTS[@]}"; do
        ssh -F ssh-config $name "ctr -n=k8s.io image import /tmp/image.tar; rm -f /tmp/image.tar" &
        pids+=($!)
    done
    # Wait for all child processes to complete
    waitForNodes "${pids[@]}"
    rm -f $SAVED_IMG
    echo "Done!"
}

function copyManifestToNodes() {
    YAML=$1
    echo "Copying $YAML to every node..."
    pids=()
    for name in "${ALL_HOSTS[@]}"; do
        scp -F ssh-config $YAML $name:~/ &
        pids+=($!)
    done
    # Wait for all child processes to complete
    waitForNodes "${pids[@]}"
    echo "Done!"
}

FLOW_AGG_YML="/tmp/flow-aggregator.yml"
SAVED_FLOW_AGG_IMG=/tmp/flow-aggregator.tar
FLOW_AGG_IMG_NAME=projects.registry.vmware.com/antrea/flow-aggregator:latest

CH_OPERATOR_INSTALL_BUNDLE_YML=$THIS_DIR/../../../../build/yamls/clickhouse-operator-install-bundle.yml
FLOW_VIS_YML="/tmp/flow-visibility.yml"

# If a flow collector address is also provided, we update the Antrea
# manifest (to enable all features)
if [[ $FLOW_COLLECTOR != "" ]]; then
    echo "Generating manifest with all features enabled along with FlowExporter feature"
    $THIS_DIR/../../../../hack/generate-manifest.sh --mode dev --all-features > "${ANTREA_YML}"
fi

# Push Antrea image and related manifest.
pushImgToNodes "$ANTREA_IMG_NAME" "$SAVED_ANTREA_IMG"
copyManifestToNodes "$ANTREA_YML"
copyManifestToNodes "$ANTREA_IPSEC_YML"

# To ensure that the most recent version of Antrea (that we just pushed) will be used.
echo "Restarting Antrea DaemonSet"
ssh -F ssh-config k8s-node-control-plane kubectl -n kube-system delete all -l app=antrea
ssh -F ssh-config k8s-node-control-plane kubectl apply -f antrea.yml

rm "${ANTREA_YML}"

# Update aggregator manifests (to set the collector address) accordingly.
if [ "$FLOW_AGGREGATOR" == "true" ]; then
    pushImgToNodes "$FLOW_AGG_IMG_NAME" "$SAVED_FLOW_AGG_IMG"
    if [[ $FLOW_COLLECTOR != "" ]]; then
        if [[ $FLOW_COLLECTOR == "ELK" ]]; then
            echo "Deploy ELK flow collector"
            echo "Copying ELK flow collector folder"
            scp -F ssh-config -r $THIS_DIR/../../../../build/yamls/elk-flow-collector k8s-node-control-plane:~/
            echo "Done copying"
            # ELK flow collector needs a few minutes (2-4 mins.) to finish its deployment,
            # so the Flow Aggregator service will not send any records till then.
            ssh -F ssh-config k8s-node-control-plane kubectl create namespace elk-flow-collector
            ssh -F ssh-config k8s-node-control-plane kubectl create configmap logstash-configmap -n elk-flow-collector --from-file=./elk-flow-collector/logstash/
            ssh -F ssh-config k8s-node-control-plane kubectl apply -f elk-flow-collector/elk-flow-collector.yml -n elk-flow-collector
            LOGSTASH_CLUSTER_IP=$(ssh -F ssh-config k8s-node-control-plane kubectl get -n elk-flow-collector svc logstash -o jsonpath='{.spec.clusterIP}')
            ELK_ADDR="${LOGSTASH_CLUSTER_IP}:4739:udp"
            $THIS_DIR/../../../../hack/generate-manifest-flow-aggregator.sh --mode dev -fc $ELK_ADDR > "${FLOW_AGG_YML}"

        elif [[ $FLOW_COLLECTOR == "Grafana" ]]; then
            echo "Deploy ClickHouse flow collector"
            # Generate manifest
            $THIS_DIR/../../../../hack/generate-manifest-flow-visibility.sh --mode dev > "${FLOW_VIS_YML}"
            $THIS_DIR/../../../../hack/generate-manifest-flow-aggregator.sh --mode dev -ch > "${FLOW_AGG_YML}"

            # Push ClickHouse Monitor image
            SAVED_CH_MONITOR_IMG=/tmp/flow-visibility-clickhouse-monitor.tar
            CH_MONITOR_IMG_NAME=projects.registry.vmware.com/antrea/flow-visibility-clickhouse-monitor:latest
            pushImgToNodes "$CH_MONITOR_IMG_NAME" "$SAVED_CH_MONITOR_IMG"

            # Copy manifests to nodes
            copyManifestToNodes "$FLOW_VIS_YML"
            copyManifestToNodes "$CH_OPERATOR_INSTALL_BUNDLE_YML"

            # Apply needed yaml files
            # Grafana flow collector needs a few minutes (2-5 mins.) to finish its deployment. It depends on the wait conditions below.
            ssh -F ssh-config k8s-node-control-plane kubectl apply -f clickhouse-operator-install-bundle.yml
            ssh -F ssh-config k8s-node-control-plane kubectl wait --for=condition=ready pod -l app=clickhouse-operator -n kube-system --timeout=180s
            ssh -F ssh-config k8s-node-control-plane kubectl apply -f flow-visibility.yml
            ssh -F ssh-config k8s-node-control-plane kubectl wait --for=condition=ready pod -l app=grafana -n flow-visibility --timeout=180s
            ssh -F ssh-config k8s-node-control-plane kubectl wait --for=condition=ready pod -l app=clickhouse -n flow-visibility --timeout=180s
            rm "${FLOW_VIS_YML}"
        else
            $THIS_DIR/../../../../hack/generate-manifest-flow-aggregator.sh --mode dev -fc $FLOW_COLLECTOR > "${FLOW_AGG_YML}"
        fi
    else
        $THIS_DIR/../../../../hack/generate-manifest-flow-aggregator.sh --mode dev > "${FLOW_AGG_YML}"
    fi

    copyManifestToNodes "$FLOW_AGG_YML"

    FLOW_VISIBILITY_CH_YML="/tmp/flow-visibility.yml"
    echo "Generating manifest for flow visibility with only clickhouse operator and db"
    $THIS_DIR/../../../../hack/generate-manifest-flow-visibility.sh --mode e2e > "${FLOW_VISIBILITY_CH_YML}"
    copyManifestToNodes "$FLOW_VISIBILITY_CH_YML"
    if [[ $FLOW_COLLECTOR != "" ]]; then
        echo "Restarting Flow Aggregator deployment"
        ssh -F ssh-config k8s-node-control-plane kubectl -n flow-aggregator delete pod --all
        ssh -F ssh-config k8s-node-control-plane kubectl apply -f flow-aggregator.yml
    fi

    rm "${FLOW_AGG_YML}"
fi

echo "Done!"
