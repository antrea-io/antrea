#!/usr/bin/env bash

# Copyright 2021 Antrea Authors
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

_usage="Usage: $0 --out <OUT_DIR> --ref <WHEREABOUTS_REF>
Build the whereabouts binaries and get them ready for upload to downloads.antrea.io
        --out <OUT_DIR>                Directory where binaries should be generated
        --ref <WHEREABOUTS_REF>        Whereabouts ref to use (tag, sha)"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

OUT_DIR=""
WHEREABOUTS_REF=""

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --out)
    OUT_DIR="$2"
    shift 2
    ;;
    --ref)
    WHEREABOUTS_REF="$2"
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

if [ "$OUT_DIR" == "" ]; then
    echoerr "--out is required"
    print_help
    exit 1
fi

if [ "$WHEREABOUTS_REF" == "" ]; then
    echoerr "--ref is required"
    print_help
    exit 1
fi

mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
FILES_DIR="$OUT_DIR/whereabouts/$WHEREABOUTS_REF"
mkdir -p "$FILES_DIR"

pushd $OUT_DIR > /dev/null

WORKDIR=$(mktemp -d $OUT_DIR/workdir.XXXXXXXX)
git clone --depth 1 --branch "$WHEREABOUTS_REF" https://github.com/k8snetworkplumbingwg/whereabouts.git $WORKDIR

pushd $WORKDIR > /dev/null

WHEREABOUTS_BUILDS=(
    "linux amd64"
    "linux arm64"
    "linux arm"
)

FILES=""
for build in "${WHEREABOUTS_BUILDS[@]}"; do
    args=($build)
    os="${args[0]}"
    arch="${args[1]}"
    name="whereabouts-${os}-${arch}"
    echoerr "Building ${name} ..."

    GOOS=$os GOARCH=$arch ./hack/build-go.sh
    mkdir $name
    mv bin/whereabouts $name/
    cp LICENSE $name/
    tar -zcvf "${FILES_DIR}/${name}.tgz" $name
    FILES="$FILES $name.tgz"
done


popd > /dev/null

rm -rf $WORKDIR

popd > /dev/null

echoerr "Files created under $FILES_DIR: $FILES"
echoerr "You can now upload $FILES_DIR to downloads.antrea.io"
