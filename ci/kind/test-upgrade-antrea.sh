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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

FROM_TAG=

_usage="Usage: $0 --from-tag <TAG>
Perform some basic tests to make sure that Antrea can be upgraded from <TAG> to the current checked-out version.
        --from-tag            Upgrade from this version of Antrea (pulled from upstream Antrea) to the current version.
        --help, -h            Print this message and exit
"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$THIS_DIR/../..

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --from-tag)
    FROM_TAG="$2"
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

rc=0
git ls-remote --heads --tags https://github.com/vmware-tanzu/antrea.git | grep -q "refs/tags/$FROM_TAG" || rc=$?
if [ $rc -ne 0 ]; then
    echoerr "$FROM_TAG is not a valid Antrea tag"
    exit 1
fi

DOCKER_IMAGES=("busybox" "antrea/antrea-ubuntu:$FROM_TAG")

for img in "${DOCKER_IMAGES[@]}"; do
    echo "Pulling $img"
    docker pull $img > /dev/null
done

DOCKER_IMAGES+=("antrea/antrea-ubuntu:latest")

echo "Creating Kind cluster"
IMAGES="${DOCKER_IMAGES[@]}"
$THIS_DIR/kind-setup.sh create kind --antrea-cni false --images "$IMAGES"

TMP_ANTREA_DIR=$(mktemp -d)
git clone --branch $FROM_TAG --depth 1 https://github.com/vmware-tanzu/antrea.git $TMP_ANTREA_DIR
pushd $TMP_ANTREA_DIR > /dev/null
export IMG_NAME=antrea/antrea-ubuntu
export IMG_TAG=$FROM_TAG
./hack/generate-manifest.sh --mode release --kind | kubectl apply -f -
./hack/generate-manifest.sh --mode release --kind | docker exec -i kind-control-plane dd of=/root/antrea.yml
popd
rm -rf $TMP_DIR

$ROOT_DIR/hack/generate-manifest.sh --kind | docker exec -i kind-control-plane dd of=/root/antrea-new.yml

rc=0
go test -v -run=TestUpgrade github.com/vmware-tanzu/antrea/test/e2e -provider=kind -upgrade.toYML=antrea-new.yml || rc=$?

$THIS_DIR/kind-setup.sh destroy kind

exit $rc
