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
FROM_VERSION_N_MINUS=
CONTROLLER_ONLY=false

_usage="Usage: $0 [--from-tag <TAG>] [--from-version-n-minus <COUNT>]
Perform some basic tests to make sure that Antrea can be upgraded from the provided version to the
current checked-out version. One of [--from-tag <TAG>] or [--from-version-n-minus <COUNT>] must be
provided.
        --from-tag <TAG>                Upgrade from this version of Antrea (pulled from upstream
                                        Antrea) to the current version.
        --from-version-n-minus <COUNT>  Get all the released versions of Antrea and run the upgrade
                                        test from the latest bug fix release for *minor* version
                                        N-{COUNT}. N-1 designates the latest minor release. If this
                                        script is run from a release branch, it will only consider
                                        releases which predate that release branch.
        --controller-only               Update antrea-controller only when upgrading.
        --help, -h                      Print this message and exit
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
    --from-version-n-minus)
    FROM_VERSION_N_MINUS="$2"
    shift 2
    ;;
    --controller-only)
    CONTROLLER_ONLY=true
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

if [ -z "$FROM_TAG" ] && [ -z "$FROM_VERSION_N_MINUS" ]; then
    echoerr "One of --from-tag or --from-version-n-minus must be provided"
    print_help
    exit 1
fi

case $FROM_VERSION_N_MINUS in
    ''|*[!0-9]*)
    echoerr "--from-version-n-minus must be a number greater than 0"
    print_help
    exit 1
    ;;
    *)
    ;;
esac

if [ ! "$FROM_VERSION_N_MINUS" -gt "0" ]; then
    echoerr "--from-version-n-minus must be a number greater than 0"
    print_help
    exit 1
fi

function version_lt() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" != "$1"; }

# We want to ignore all minor versions greater than the current version, as an upgrade test implies
# that we are upgrading from an *older* version. This is useful when running this script from a
# release branch (e.g. when testing patch release candidates).
CURRENT_VERSION=$(head -n1 $ROOT_DIR/VERSION)
CURRENT_VERSION=${CURRENT_VERSION:1} # strip leading 'v'
CURRENT_VERSION=${CURRENT_VERSION%-*} # strip "-dev" suffix if present

# Exclude peeled tags and release candidates from the version list.
VERSIONS=$(git ls-remote --tags --ref https://github.com/vmware-tanzu/antrea.git | \
               grep -v rc | \
               awk '{print $2}' | awk -F/ '{print $3}' | \
               sort --version-sort -r)

if [ ! -z "$FROM_TAG" ]; then
    rc=0
    echo "$VERSIONS" | grep -q "$FROM_TAG" || rc=$?
    if [ $rc -ne 0 ]; then
        echoerr "$FROM_TAG is not a valid Antrea tag"
        exit 1
    fi
else # Set FROM_TAG using the provided FROM_VERSION_N_MINUS value
    arr=( ${CURRENT_VERSION//./ } ) # x.y.z -> (x y z)
    minor_version="${arr[0]}.${arr[1]}"
    count=
    for version in $VERSIONS; do
        version_nums=${version:1} # strip leading 'v'
        arr=( ${version_nums//./ } ) # x.y.z -> (x y z)
        new_minor_version="${arr[0]}.${arr[1]}"
        if version_lt $new_minor_version $minor_version; then # change in minor version, increase $count
            ((count+=1))
            minor_version=$new_minor_version
            if [ "$count" == "$FROM_VERSION_N_MINUS" ]; then # we went back enough, use this version
                FROM_TAG="$version"
                break
            fi
        fi
    done

    if [ -z "$FROM_TAG" ]; then
        echoerr "Cannot determine tag for provided --from-version-n-minus value"
        exit 1
    fi
fi

echo "Running upgrade test for tag $FROM_TAG"

DOCKER_IMAGES=("busybox" "projects.registry.vmware.com/antrea/antrea-ubuntu:$FROM_TAG")

for img in "${DOCKER_IMAGES[@]}"; do
    echo "Pulling $img"
    docker pull $img > /dev/null
done

DOCKER_IMAGES+=("projects.registry.vmware.com/antrea/antrea-ubuntu:latest")

echo "Creating Kind cluster"
IMAGES="${DOCKER_IMAGES[@]}"
$THIS_DIR/kind-setup.sh create kind --antrea-cni false --images "$IMAGES"

# When running this script as part of a Github Action, we do *not* want to use
# the pre-installed version of kustomize, as it is a snap and cannot access
# /tmp. See:
#  * https://github.com/actions/virtual-environments/issues/1514
#  * https://forum.snapcraft.io/t/interfaces-allow-access-tmp-directory/5129
# "--on-delete" is specified so that the upgrade can be done in a controlled
# fashion, e.g. upgrading controller only and specific antrea-agents for
# compatibility test.
unset KUSTOMIZE
$ROOT_DIR/hack/generate-manifest.sh --kind --on-delete | docker exec -i kind-control-plane dd of=/root/antrea-new.yml

TMP_ANTREA_DIR=$(mktemp -d)
git clone --branch $FROM_TAG --depth 1 https://github.com/vmware-tanzu/antrea.git $TMP_ANTREA_DIR
pushd $TMP_ANTREA_DIR > /dev/null
export IMG_NAME=projects.registry.vmware.com/antrea/antrea-ubuntu
export IMG_TAG=$FROM_TAG
./hack/generate-manifest.sh --mode release --kind | kubectl apply -f -
./hack/generate-manifest.sh --mode release --kind | docker exec -i kind-control-plane dd of=/root/antrea.yml
popd
rm -rf $TMP_DIR

rc=0
go test -v -run=TestUpgrade github.com/vmware-tanzu/antrea/test/e2e -provider=kind -upgrade.toYML=antrea-new.yml --upgrade.controllerOnly=$CONTROLLER_ONLY --logs-export-dir=$ANTREA_LOG_DIR || rc=$?

$THIS_DIR/kind-setup.sh destroy kind

exit $rc
