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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--mode (dev|release|e2e)] [--keep] [--help|-h]
Generate a YAML manifest for the ClickHouse-Grafana Flow-visibility Solution, using Kustomize, and
print it to stdout.
        --mode (dev|release|e2e)    Choose the configuration variant that you need (default is 'dev')
                                    e2e mode generates YAML manifest for e2e test, which includes
                                    ClickHouse operator and server with default credentials,
                                    but not Grafana-related functionality and ClickHouse monitor.
        --keep                      Debug flag which will preserve the generated kustomization.yml
        --volume (ram|pv)           Choose the volume provider that you need (default is 'ram').
        --storageclass -sc <name>   Provide the StorageClass used to dynamically provision the 
                                    PersistentVolume for ClickHouse storage.
        --local <path>              Create the PersistentVolume for ClickHouse with a provided
                                    local path.
        --nfs <hostname:path>       Create the PersistentVolume for ClickHouse with a provided
                                    NFS server hostname or IP address and the path exported in the
                                    form of hostname:path.
        --size <size>               Deploy the ClickHouse with a specific storage size. Can be a 
                                    plain integer or as a fixed-point number using one of these quantity
                                    suffixes: E, P, T, G, M, K. Or the power-of-two equivalents:
                                    Ei, Pi, Ti, Gi, Mi, Ki.  The default is 8Gi.
        --help, -h                  Print this message and exit
This tool uses kustomize (https://github.com/kubernetes-sigs/kustomize) to generate manifests for
ClickHouse-Grafana Flow-visibility Solution. You can set the KUSTOMIZE environment variable to the
path of the kustomize binary you want us to use. Otherwise we will look for kustomize in your PATH
and your GOPATH. If we cannot find kustomize there, we will try to install it."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
KEEP=false
VOLUME="ram"
STORAGECLASS=""
LOCALPATH=""
NFSPATH=""
SIZE="8Gi"

while [[ $# -gt 0 ]]
do
key="$1"
case $key in
    --mode)
    MODE="$2"
    shift 2
    ;;
    --keep)
    KEEP=true
    shift
    ;;
    --volume)
    VOLUME="$2"
    shift 2
    ;;
    -sc|--storageclass)
    STORAGECLASS="$2"
    shift 2
    ;;
    --local)
    LOCALPATH="$2"
    shift 2
    ;;
    --nfs)
    NFSPATH="$2"
    shift 2
    ;;
    --size)
    SIZE="$2"
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

if [ "$MODE" != "dev" ] && [ "$MODE" != "release" ] && [ "$MODE" != "e2e" ]; then
    echoerr "--mode must be one of 'dev', 'release' or 'e2e'"
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

if [ "$VOLUME" != "ram" ] && [ "$VOLUME" != "pv" ]; then
    echoerr "--volume must be one of 'ram' or 'pv'"
    print_help
    exit 1
fi

if [ "$VOLUME" == "pv" ] && [ "$LOCALPATH" == "" ] && [ "$NFSPATH" == "" ] && [ "$STORAGECLASS" == "" ]; then
    echoerr "When deploying with 'pv', one of '--local', '--nfs', '--storageclass' should be set"
    print_help
    exit 1
fi

if ([ "$LOCALPATH" != "" ] && [ "$NFSPATH" != "" ]) || ([ "$LOCALPATH" != "" ] && [ "$STORAGECLASS" != "" ]) || ([ "$STORAGECLASS" != "" ] && [ "$NFSPATH" != "" ]); then
    echoerr "Cannot set '--local', '--nfs' or '--storageclass' at the same time"
    print_help
    exit 1
fi

if [ "$NFSPATH" != "" ]; then
    pathPair=(${NFSPATH//:/ })
    if [ ${#pathPair[@]} != 2 ]; then
        echoerr "--nfs must be in the form of hostname:path"
        print_help
        exit 1
    fi
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

KUSTOMIZATION_DIR=$THIS_DIR/../build/yamls/flow-visibility

TMP_DIR=$(mktemp -d $KUSTOMIZATION_DIR/overlays.XXXXXXXX)

pushd $TMP_DIR > /dev/null

BASE=../../base

mkdir $MODE && cd $MODE
touch kustomization.yml
# ../../patches/$MODE may be empty so we use find and not simply cp
find ../../patches/$MODE -name \*.yml -exec cp {} . \;

if [ "$MODE" == "e2e" ]; then
    mkdir -p base/provisioning/datasources
    cp $KUSTOMIZATION_DIR/base/clickhouse.yml base/clickhouse.yml
    cp $KUSTOMIZATION_DIR/base/kustomization-e2e.yml base/kustomization.yml
    cp $KUSTOMIZATION_DIR/base/kustomize-config.yml base/kustomize-config.yml
    cp $KUSTOMIZATION_DIR/base/provisioning/datasources/create_table.sh base/provisioning/datasources/create_table.sh
    cp $KUSTOMIZATION_DIR/../clickhouse-operator-install-bundle.yml clickhouse-operator-install-bundle.yml
    $KUSTOMIZE edit add base base
    $KUSTOMIZE edit add patch --path imagePullPolicyClickhouse.yml --group clickhouse.altinity.com --version v1 --kind ClickHouseInstallation --name clickhouse
else
    # patch the clickhouse monitor with desired storage size
    cp $KUSTOMIZATION_DIR/patches/chmonitor/*.yml .
    $KUSTOMIZE edit add base $BASE
    sed -i.bak -E "s/STORAGE_SIZE_VALUE/$SIZE/" chMonitor.yml
    $KUSTOMIZE edit add patch --path chMonitor.yml --group clickhouse.altinity.com --version v1 --kind ClickHouseInstallation --name clickhouse
fi

if [ "$MODE" == "dev" ]; then
    $KUSTOMIZE edit set image flow-visibility-clickhouse-monitor=projects.registry.vmware.com/antrea/flow-visibility-clickhouse-monitor:latest
    $KUSTOMIZE edit add patch --path imagePullPolicy.yml --group clickhouse.altinity.com --version v1 --kind ClickHouseInstallation --name clickhouse
fi

if [ "$MODE" == "release" ]; then
    $KUSTOMIZE edit set image flow-visibility-clickhouse-monitor=$IMG_NAME:$IMG_TAG
fi
BASE=../$MODE
cd ..

if [ "$VOLUME" == "ram" ]; then
    mkdir ram && cd ram
    cp $KUSTOMIZATION_DIR/patches/ram/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    sed -i.bak -E "s/STORAGE_SIZE/$SIZE/" mountRam.yml
    $KUSTOMIZE edit add patch --path mountRam.yml --group clickhouse.altinity.com --version v1 --kind ClickHouseInstallation --name clickhouse
fi

if [ "$VOLUME" == "pv" ]; then
    mkdir pv && cd pv
    cp $KUSTOMIZATION_DIR/patches/pv/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE

    if [[ $STORAGECLASS != "" ]]; then
        sed -i.bak -E "s/STORAGECLASS_NAME/$STORAGECLASS/" mountPv.yml
    else
        sed -i.bak -E "s/STORAGECLASS_NAME/clickhouse-storage/" mountPv.yml
    fi
    if [[ $LOCALPATH != "" ]]; then
        sed -i.bak -E "s~LOCAL_PATH~$LOCALPATH~" createLocalPv.yml
        sed -i.bak -E "s/STORAGE_SIZE/$SIZE/" createLocalPv.yml
        $KUSTOMIZE edit add base createLocalPv.yml
    fi
    if [[ $NFSPATH != "" ]]; then
        sed -i.bak -E "s~NFS_SERVER_ADDRESS~${pathPair[0]}~" createNfsPv.yml
        sed -i.bak -E "s~NFS_SERVER_PATH~${pathPair[1]}~" createNfsPv.yml
        sed -i.bak -E "s/STORAGE_SIZE/$SIZE/" createNfsPv.yml
        $KUSTOMIZE edit add base createNfsPv.yml
    fi
    sed -i.bak -E "s/STORAGE_SIZE/$SIZE/" mountPv.yml
    $KUSTOMIZE edit add patch --path mountPv.yml --group clickhouse.altinity.com --version v1 --kind ClickHouseInstallation --name clickhouse
fi

$KUSTOMIZE build

popd > /dev/null

if $KEEP; then
    echoerr "Kustomization file is at $TMP_DIR/$MODE/kustomization.yml"
else
    rm -rf $TMP_DIR
fi
