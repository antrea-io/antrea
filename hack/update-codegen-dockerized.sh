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

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

GOPATH=`go env GOPATH`
ANTREA_PKG="github.com/vmware-tanzu/antrea"

# Generate protobuf code for CNI gRPC service with protoc.
protoc --go_out=plugins=grpc:. pkg/apis/cni/v1beta1/cni.proto

# Generate clientset and apis code with K8s codegen tools.
$GOPATH/bin/client-gen \
  --clientset-name versioned \
  --input-base "${ANTREA_PKG}/pkg/apis/" \
  --input "clusterinformation/v1beta1,networking/v1beta1" \
  --output-package "${ANTREA_PKG}/pkg/client/clientset" \
  --go-header-file hack/boilerplate/license_header.go.txt

$GOPATH/bin/deepcopy-gen \
  --input-dirs "${ANTREA_PKG}/pkg/apis/clusterinformation/v1beta1,${ANTREA_PKG}/pkg/apis/networking,${ANTREA_PKG}/pkg/apis/networking/v1beta1" \
  -O zz_generated.deepcopy \
  --go-header-file hack/boilerplate/license_header.go.txt

$GOPATH/bin/conversion-gen  \
  --input-dirs "${ANTREA_PKG}/pkg/apis/networking/v1beta1,${ANTREA_PKG}/pkg/apis/networking/" \
  -O zz_generated.conversion \
  --go-header-file hack/boilerplate/license_header.go.txt

$GOPATH/bin/openapi-gen  \
  --input-dirs "${ANTREA_PKG}/pkg/apis/networking/v1beta1" \
  --input-dirs "k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/util/intstr" \
  --output-package "${ANTREA_PKG}/pkg/apiserver/openapi" \
  -O zz_generated.openapi \
  --go-header-file hack/boilerplate/license_header.go.txt

# Generate mocks for testing with mockgen.
MOCKGEN_TARGETS=(
  "pkg/agent/cniserver/ipam IPAMDriver"
  "pkg/agent/openflow Client,FlowOperations"
  "pkg/ovs/openflow Bridge,Table,Flow,Action,FlowBuilder"
  "pkg/ovs/ovsconfig OVSBridgeClient"
  "pkg/monitor AgentQuerier,ControllerQuerier"
)

for target in "${MOCKGEN_TARGETS[@]}"; do
  read -r package interfaces <<<"${target}"
  package_name=$(basename "${package}")
  $GOPATH/bin/mockgen \
    -copyright_file hack/boilerplate/license_header.raw.txt \
    -destination "${package}/testing/mock_${package_name}.go" \
    -package=testing \
    "${ANTREA_PKG}/${package}" "${interfaces}"
done

# Download vendored modules to the vendor directory so it's easier to
# specify the search path of required protobuf files.
go mod vendor
$GOPATH/bin/go-to-protobuf \
  --proto-import vendor \
  --packages "${ANTREA_PKG}/pkg/apis/networking/v1beta1" \
  --go-header-file hack/boilerplate/license_header.go.txt
# Clean up vendor directory.
rm -rf vendor

