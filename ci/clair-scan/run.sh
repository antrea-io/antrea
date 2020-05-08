#!/usr/bin/env bash

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$THIS_DIR" > /dev/null

# The highest Antrea release version.
VERSION=$(git ls-remote --tags https://github.com/vmware-tanzu/antrea.git | awk '{print $2}' | awk -F/ '{print $3}' | sort --version-sort -r | head -n 1)

echo "Scanning Antrea version $VERSION"

docker pull "antrea/antrea-ubuntu:$VERSION"
docker pull "antrea/antrea-ubuntu:latest"

echo "Downloading clair-scanner"
curl -Lo ./clair-scanner https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64
chmod +x clair-scanner

echo  "Start Clair server and database"
# See https://github.com/arminc/clair-scanner for details
docker run --rm -d --name clair-db arminc/clair-db:latest
docker run --rm -p 6060:6060 --link clair-db:postgres -d --name clair arminc/clair-local-scan:v2.0.8_fe9b059d930314b54c78f75afe265955faf4fdc1

function cleanup {
  echo "Killing docker containers"
  docker kill clair
  docker kill clair-db
}

trap cleanup EXIT

# Required to run clair-scanner
DOCKER_BRIDGE_IP=$(docker network inspect bridge | jq -r '.[0].IPAM.Config[0].Gateway')

./clair-scanner --clair=http://localhost:6060 --ip "$DOCKER_BRIDGE_IP" -r "clair.$VERSION.json" "antrea/antrea-ubuntu:$VERSION" || test -f "clair.$VERSION.json"
./clair-scanner --clair=http://localhost:6060 --ip "$DOCKER_BRIDGE_IP" -r "clair.latest.json" "antrea/antrea-ubuntu:latest" || test -f "clair.latest.json"

go run . --report "clair.$VERSION.json" --report-cmp "clair.latest.json"
