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

# get and install specific version of code-generator which is compatible with apimachinery
go get -m k8s.io/code-generator@release-1.14
go install k8s.io/code-generator/cmd/{defaulter-gen,client-gen,lister-gen,informer-gen,deepcopy-gen}

# re-generate both client and deepcopy for monitoring api
# position generate client to its desired location
export GOPATH=`go env GOPATH`
$GOPATH/bin/client-gen \
  --clientset-name "versioned" \
  --input-base "github.com/vmware-tanzu/antrea/pkg/apis/" \
  --input "clusterinformation/crd/antrea/v1beta1,networkpolicy/v1beta1" \
  --output-base "$(dirname "${BASH_SOURCE[0]}")/../../../../" \
  --output-package "github.com/vmware-tanzu/antrea/pkg/client/clientset" \
  --go-header-file hack/boilerplate/license_header.go.txt

$GOPATH/bin/deepcopy-gen \
  --input-dirs "github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/crd/antrea/v1beta1,github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy,github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy/v1beta1" \
  --bounding-dirs "github.com/vmware-tanzu/antrea/pkg/apis" \
  -O zz_generated.deepcopy \
  --go-header-file hack/boilerplate/license_header.go.txt

$GOPATH/bin/conversion-gen  \
  -i "github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy/v1beta1,github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy/" \
  -O zz_generated.conversion \
  --go-header-file hack/boilerplate/license_header.go.txt
