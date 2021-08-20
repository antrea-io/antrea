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
set -o nounset
set -o pipefail

ANTREA_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../../" && pwd )"
IMAGE_NAME="antrea/codegen:kubernetes-1.21.0"

function docker_run() {
  docker pull ${IMAGE_NAME}
  docker run --rm \
		-w /go/src/antrea.io/antrea \
		-v ${ANTREA_ROOT}:/go/src/antrea.io/antrea \
		"${IMAGE_NAME}" "$@"
}

docker_run multicluster/hack/update-codegen-dockerized.sh
