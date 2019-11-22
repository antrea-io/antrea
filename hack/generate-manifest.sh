#!/usr/bin/env bash

# Copyright 2019 Antrea Authors
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

_usage="Usage: $0 [--mode (dev|release)] [--kind] [--keep] [--help|-h]
Generate a YAML manifest for Antrea using Kustomize and print it to stdout.
        --mode (dev|release)  Choose the configuration variant that you need (default is 'dev')
        --kind                Generate a manifest appropriate for running Antrea in a Kind cluster
        --keep                Debug flag which will preserve the generated kustomization.yml
        --help, -h            Print this message and exit

In 'release' mode, environment variables IMG_NAME and IMG_TAG must be set.

This tool uses kustomize (https://github.com/kubernetes-sigs/kustomize) to generate manifests for
Antrea. You can set the KUSTOMIZE environment variable to the path of the kustomize binary you want
us to use. Otherwise we will look for kustomize in your PATH and your GOPATH. If we cannot find
kustomize there, we will try to install it."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
KIND=false
KEEP=false

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --mode)
    MODE="$2"
    shift 2
    ;;
    --kind)
    KIND=true
    shift
    ;;
    --keep)
    KEEP=true
    shift
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

if [ "$MODE" != "dev" ] && [ "$MODE" != "release" ]; then
    echoerr "--mode must be one of 'dev' or 'release'"
    print_help
    exit 1
fi

if [ "$MODE" == "release" ] && [ -z "$IMG_NAME" ]; then
    echoerr "In 'release' mode, environment variable IMG_NAME must be set"
    print_help
    exit 1
fi

if [ "$MODE" == "release" ] && [ -z "$IMG_TAG" ]; then
    echoerr "In 'release' mode, environment variable IMG_TAG must be set"
    print_help
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/verify-kustomize.sh

if [ -z "$KUSTOMIZE" ]; then
    KUSTOMIZE="$(verify_kustomize)"
elif ! $KUSTOMIZE version > /dev/null 2>&1; then
    echoerr "$KUSTOMIZE does not appear to be a valid kustomize binary"
    print_help
    exit 1
fi

KUSTOMIZATION_DIR=$THIS_DIR/../build/yamls/overlays

TMP_DIR=$(mktemp -d $KUSTOMIZATION_DIR/$MODE.XXXXXXXX)

pushd $TMP_DIR > /dev/null

touch kustomization.yml
$KUSTOMIZE edit add base ../$MODE

if [ "$MODE" == "dev" ]; then
    # nothing to do for now, everything is taken care of in the overlay kustomization.yml.
    :
fi

if [ "$MODE" == "release" ]; then
    $KUSTOMIZE edit set image antrea=$IMG_NAME:$IMG_TAG
fi

if $KIND; then
    # we copy the patch files to avoid having to use the '--load-restrictor. flag when calling
    # 'kustomize build'. See https://github.com/kubernetes-sigs/kustomize/blob/master/docs/FAQ.md#security-file-foo-is-not-in-or-below-bar
    cp ../../patches/kind/*.yml .

    # add tun device to antrea OVS container
    $KUSTOMIZE edit add patch tunDevice.yml
    # edit antrea Agent configuration to use the netdev datapath
    $KUSTOMIZE edit add patch ovsDatapath.yml
    # antrea-ovs should use start_ovs_netdev instead of start_ovs to ensure that the br_phy bridge
    # is created.
    $KUSTOMIZE edit add patch startOvs.yml
    # change initContainer script and remove SYS_MODULE capability
    $KUSTOMIZE edit add patch installCni.yml
fi

$KUSTOMIZE build

popd > /dev/null

if $KEEP; then
    echoerr "Kustomization file is at $TMP_DIR/kustomization.yml"
else
    rm -rf $TMP_DIR
fi
