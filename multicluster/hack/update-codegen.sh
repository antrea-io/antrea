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

set -o errexit
set -o pipefail

ANTREA_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../../" && pwd )"
IMAGE_NAME="antrea/codegen:kubernetes-1.29.2-build.0"

# Recent versions of Git will not access .git directories which are owned by
# another user (as a security measure), unless the directories are explicitly
# added to a "safe" list in the Git config. When we run the Docker container,
# the Antrea source directory may be owned (depends on the Docker platform)
# by a user which is different from the container user (as the source directory
# is mounted from the host). If this is the case, the Git program inside the
# container will refuse to run. This is why we explicitly add the Antrea source
# directory to the list of "safe" directories. We are still looking into the
# possibility of running the Docker container as the "current host user".
function docker_run() {
  # Silence CLI suggestions.
  export DOCKER_CLI_HINTS=false
  docker pull ${IMAGE_NAME}
  set -x
  ANTREA_PATH="/go/src/antrea.io/antrea"
  docker run --rm \
		-e GOPROXY=${GOPROXY} \
		-w ${ANTREA_PATH} \
		-v ${ANTREA_ROOT}:${ANTREA_PATH} \
		"${IMAGE_NAME}" bash -c "git config --global --add safe.directory ${ANTREA_PATH} && $@"
}

docker_run multicluster/hack/update-codegen-dockerized.sh $@
