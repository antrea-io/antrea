#!/usr/bin/env bash

function usage() {
    echo "Usage: push_antrea.sh [--prometheus] [-fc|--flow-collector <Address>] [-fa|--flow-aggregator] [-h|--help]
    Push the latest Antrea image to all vagrant nodes and restart the Antrea daemons
          --prometheus                Deploy Prometheus service to scrape metrics from Antrea Agents and Controllers
          --flow-collector <Address>  Provide the IPFIX flow collector address to collect the flows from the Flow Aggregator service
                                      It should be given in the format IP:port:proto. Example: 192.168.1.100:4739:udp
                                      Please note that with this option we deploy the Flow Aggregator Service along with Antrea.
          --flow-aggregator           Deploy Flow Aggregator along with Antrea.
                                      It is automatically deployed if --flow-collector is used."
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

: "${NUM_WORKERS:=1}"
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
    # Copy image to control-plane node
    scp -F ssh-config $SAVED_IMG k8s-node-control-plane:/tmp/image.tar &
    pids[0]=$!
    # Loop over all worker nodes and copy image to each one
    for ((i=1; i<=$NUM_WORKERS; i++)); do
        name="k8s-node-worker-$i"
        scp -F ssh-config $SAVED_IMG $name:/tmp/image.tar &
        pids[$i]=$!
    done
    # Wait for all child processes to complete
    waitForNodes "${pids[@]}"
    echo "Done!"

    echo "Loading $IMG_NAME image in every node..."
    ssh -F ssh-config k8s-node-control-plane "docker load -i /tmp/image.tar; rm -f /tmp/image.tar" &
    pids[0]=$!
    # Loop over all worker nodes and copy image to each one
    for ((i=1; i<=$NUM_WORKERS; i++)); do
        name="k8s-node-worker-$i"
        ssh -F ssh-config $name "docker load -i /tmp/image.tar; rm -f /tmp/image.tar" &
        pids[$i]=$!
    done
    # Wait for all child processes to complete
    waitForNodes "${pids[@]}"
    rm -f $SAVED_IMG
    echo "Done!"
}

function copyManifestToNodes() {
    YAML=$1
    echo "Copying $YAML to every node..."
    scp -F ssh-config $YAML k8s-node-control-plane:~/ &
    pids[0]=$!
    # Loop over all worker nodes and copy manifest to each one
    for ((i=1; i<=$NUM_WORKERS; i++)); do
        name="k8s-node-worker-$i"
        scp -F ssh-config $YAML $name:~/ &
        pids[$i]=$!
    done
    # Wait for all child processes to complete
    waitForNodes "${pids[@]}"
    echo "Done!"
}

FLOW_AGG_YML="/tmp/flow-aggregator.yml"
SAVED_FLOW_AGG_IMG=/tmp/flow-aggregator.tar
FLOW_AGG_IMG_NAME=projects.registry.vmware.com/antrea/flow-aggregator:latest
if [ "$FLOW_AGGREGATOR" == "true" ]; then
    pushImgToNodes "$FLOW_AGG_IMG_NAME" "$SAVED_FLOW_AGG_IMG"

    # If a flow collector address is also provided, we update the Antrea
    # manifest (to enable all features) and Aggregator manifests (to set the
    # collector address) accordingly.
    if [[ $FLOW_COLLECTOR != "" ]]; then
        echo "Generating manifest with all features enabled along with FlowExporter feature"
        $THIS_DIR/../../../../hack/generate-manifest.sh --mode dev --all-features > "${ANTREA_YML}"

        $THIS_DIR/../../../../hack/generate-manifest-flow-aggregator.sh --mode dev -fc $FLOW_COLLECTOR > "${FLOW_AGG_YML}"
    else
        $THIS_DIR/../../../../hack/generate-manifest-flow-aggregator.sh --mode dev > "${FLOW_AGG_YML}"
    fi

    copyManifestToNodes "$FLOW_AGG_YML"

    echo "Restarting Flow Aggregator deployment"
    ssh -F ssh-config k8s-node-control-plane kubectl -n flow-aggregator delete pod --all
    ssh -F ssh-config k8s-node-control-plane kubectl apply -f flow-aggregator.yml

    rm "${FLOW_AGG_YML}"
fi

# Push Antrea image and related manifest.
pushImgToNodes "$ANTREA_IMG_NAME" "$SAVED_ANTREA_IMG"
copyManifestToNodes "$ANTREA_YML"
copyManifestToNodes "$ANTREA_IPSEC_YML"

# To ensure that the most recent version of Antrea (that we just pushed) will be
# used.
echo "Restarting Antrea DaemonSet"
ssh -F ssh-config k8s-node-control-plane kubectl -n kube-system delete all -l app=antrea
ssh -F ssh-config k8s-node-control-plane kubectl apply -f antrea.yml

rm "${ANTREA_YML}"

echo "Done!"
