#!/usr/bin/env bash

function usage() {
    echo "Usage: push_antrea.sh [--prometheus] [-h|--help]"
}

# Process execution flags
RUN_PROMETHEUS=false
for i in "$@"; do
    case $i in
        --prometheus)
            RUN_PROMETHEUS=true
            shift
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
SAVED_IMG=/tmp/antrea-ubuntu.tar
IMG_NAME=projects.registry.vmware.com/antrea/antrea-ubuntu:latest

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

docker inspect $IMG_NAME > /dev/null
if [ $? -ne 0 ]; then
    echo "Docker image $IMG_NAME was not found"
    exit 1
fi

echo "Saving $IMG_NAME image to $SAVED_IMG"
docker save -o $SAVED_IMG $IMG_NAME

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

echo "Copying $IMG_NAME image to every node..."
# Copy image to master
scp -F ssh-config $SAVED_IMG k8s-node-master:/tmp/antrea-ubuntu.tar &
pids[0]=$!
# Loop over all worker nodes and copy image to each one
for ((i=1; i<=$NUM_WORKERS; i++)); do
    name="k8s-node-worker-$i"
    scp -F ssh-config $SAVED_IMG $name:/tmp/antrea-ubuntu.tar &
    pids[$i]=$!
done
# Wait for all child processes to complete
waitForNodes "${pids[@]}"
echo "Done!"

echo "Loading $IMG_NAME image in every node..."
ssh -F ssh-config k8s-node-master docker load -i /tmp/antrea-ubuntu.tar &
pids[0]=$!
# Loop over all worker nodes and copy image to each one
for ((i=1; i<=$NUM_WORKERS; i++)); do
    name="k8s-node-worker-$i"
    ssh -F ssh-config $name docker load -i /tmp/antrea-ubuntu.tar &
    pids[$i]=$!
done
# Wait for all child processes to complete
waitForNodes "${pids[@]}"
echo "Done!"

echo "Copying Antrea deployment YAML to every node..."
scp -F ssh-config $ANTREA_YML $ANTREA_IPSEC_YML k8s-node-master:~/ &
pids[0]=$!
# Loop over all worker nodes and copy image to each one
for ((i=1; i<=$NUM_WORKERS; i++)); do
    name="k8s-node-worker-$i"
    scp -F ssh-config $ANTREA_YML $ANTREA_IPSEC_YML $name:~/ &
    pids[$i]=$!
done
# Wait for all child processes to complete
waitForNodes "${pids[@]}"
echo "Done!"

# To ensure that the most recent version of Antrea (that we just pushed) will be
# used.
echo "Restarting Antrea DaemonSet"
ssh -F ssh-config k8s-node-master kubectl -n kube-system delete all -l app=antrea
ssh -F ssh-config k8s-node-master kubectl apply -f antrea.yml

rm "${ANTREA_YML}"

echo "Done!"
