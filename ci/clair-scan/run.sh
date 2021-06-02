#!/usr/bin/env bash

set -eo pipefail

ostype=""
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    ostype="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    ostype="darwin"
else
    echo "Unsupported OS type $OSTYPE"
    exit 1
fi

if [ -n "$1" ]; then
    REPORTS_OUT_DIR=$(cd "$1" && pwd)
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$THIS_DIR" > /dev/null

# The highest Antrea release version, excluding release candidates.
# We also exclude peeled tags from the output (vX.Y.Z^{}) as they could lead to
# an invalid version number.
VERSION=$(git ls-remote --tags --ref https://github.com/antrea-io/antrea.git | \
              grep -v rc | \
              awk '{print $2}' | awk -F/ '{print $3}' | \
              sort --version-sort -r | head -n 1)

echo "Scanning Antrea version $VERSION"

docker pull "antrea/antrea-ubuntu:$VERSION"
docker pull "antrea/antrea-ubuntu:latest"

echo "Downloading clair-scanner"
curl -Lo ./clair-scanner "https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_${ostype}_amd64"
chmod +x clair-scanner

echo  "Start Clair server and database"
# See https://github.com/arminc/clair-scanner for details
docker run --rm -d --name clair-db arminc/clair-db:latest
docker run --rm -p 6060:6060 --link clair-db:postgres -d --name clair arminc/clair-local-scan:v2.0.8_fe9b059d930314b54c78f75afe265955faf4fdc1

function cleanup {
  echo "Stopping docker containers"
  docker kill clair || true
  docker kill clair-db || true
}

trap cleanup EXIT

# Required to run clair-scanner, we need to be able to access clair-scanner
# (running on the host) from within the docker containers.
CLAIR_SCANNER_IP=""
if [ "$ostype" == "linux" ]; then
    # on Linux, use docker bridge IP.
    DOCKER_BRIDGE_IP=$(docker network inspect bridge | jq -r '.[0].IPAM.Config[0].Gateway')
    CLAIR_SCANNER_IP="$DOCKER_BRIDGE_IP"
else
    # on macOS, use the IP address assigned to en0, since docker containers run
    # within a VM, and that's where the docker bridge is created. This should
    # work most of the time.
    EN0_IP=$(ip addr show en0 | grep "inet " | awk '{ print $2 }' | awk -F "/" '{ print $1 }')
    CLAIR_SCANNER_IP="$EN0_IP"
fi

./clair-scanner --clair=http://localhost:6060 --ip "$CLAIR_SCANNER_IP" -r "clair.$VERSION.json" "antrea/antrea-ubuntu:$VERSION" || test -f "clair.$VERSION.json"
./clair-scanner --clair=http://localhost:6060 --ip "$CLAIR_SCANNER_IP" -r "clair.latest.json" "antrea/antrea-ubuntu:latest" || test -f "clair.latest.json"

if [ -n "$REPORTS_OUT_DIR" ]; then
    echo "Copying Clair scan reports to $REPORTS_OUT_DIR"
    cp "clair.$VERSION.json" "clair.latest.json" "$REPORTS_OUT_DIR"
fi

go run . --report "clair.$VERSION.json" --report-cmp "clair.latest.json"
