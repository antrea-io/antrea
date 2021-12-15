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

_usage="Usage: $0 [--global|-g] [--leader|-l <namespace>] [--member|-m] [--help|-h]
Generate a YAML manifest for Antrea MultiCluster using Kustomize and print it to stdout.
        --global                       Generate a global manifest for a Cluster as leader in a ClusterSet
        --leader                       Generate a per-namespace manifest for a Cluster as leader in a ClusterSet.
                                       All resources will be in the given namespace
        --member                       Generate a manifest for a Cluster as member in a ClusterSet
        --help, -h                     Print this message and exit

This tool uses kustomize (https://github.com/kubernetes-sigs/kustomize) to generate manifests for
Antrea MultiCluster Controller. please run 'make kustomize' first"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

OVERLAY=member
NAMESPACE=changeme

while getopts gl:mhu flag
do
    case "${flag}" in
        g)
          OVERLAY=leader-global
          ;;
        l)
          OVERLAY=leader-ns
          NAMESPACE=$OPTARG
          ;;
        m)
          OVERLAY=member
          ;;
        h)
          print_help
          exit 0
          ;;
        u | *)
          print_usage
          exit 0
          ;;
    esac
done

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

KUSTOMIZE=$THIS_DIR/../bin/kustomize

KUSTOMIZATION_DIR=$THIS_DIR/../config

cd $KUSTOMIZATION_DIR

if [ "$OVERLAY" == "leader-ns" ] ;
then
    TMP_DIR=$(mktemp -d $KUSTOMIZATION_DIR/overlays.XXXXXXXX)
    pushd $TMP_DIR > /dev/null
    mkdir config && cd config
    cp $KUSTOMIZATION_DIR/overlays/leader-ns/prefix_transformer.yaml .
    sed -ie "s/changeme/$NAMESPACE/g" prefix_transformer.yaml

cat << EOF > kustomization.yaml
namespace: $NAMESPACE

bases:
  - ../../overlays/leader-ns

transformers:
  - prefix_transformer.yaml
EOF
    $KUSTOMIZE build
    rm -rf $TMP_DIR
else
    $KUSTOMIZE build overlays/$OVERLAY
fi
