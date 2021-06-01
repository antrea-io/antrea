#!/usr/bin/env bash

function usage() {
    echo "Usage: push_image.sh"
}

: "${NUM_WORKERS:=1}"
SAVED_IMG=/tmp/antrea-scale.tar
IMG_NAME=antrea/antrea-scale:latest
SSH_CONFIG=../test/e2e/infra/vagrant/ssh-config


THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $THIS_DIR

if [ ! -f $SSH_CONFIG ]; then
    echo "File ssh-config does not exist."
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
scp -F $SSH_CONFIG $SAVED_IMG k8s-node-master:/tmp/antrea-ubuntu.tar &
pids[0]=$!
# Loop over all worker nodes and copy image to each one
for ((i=1; i<=$NUM_WORKERS; i++)); do
    name="k8s-node-worker-$i"
    scp -F $SSH_CONFIG $SAVED_IMG $name:/tmp/antrea-ubuntu.tar &
    pids[$i]=$!
done
# Wait for all child processes to complete
waitForNodes "${pids[@]}"
echo "Done!"

echo "Loading $IMG_NAME image in every node..."
ssh -F $SSH_CONFIG k8s-node-master docker load -i /tmp/antrea-ubuntu.tar &
pids[0]=$!
# Loop over all worker nodes and copy image to each one
for ((i=1; i<=$NUM_WORKERS; i++)); do
    name="k8s-node-worker-$i"
    ssh -F $SSH_CONFIG $name docker load -i /tmp/antrea-ubuntu.tar &
    pids[$i]=$!
done
# Wait for all child processes to complete
waitForNodes "${pids[@]}"
echo "Done!"
