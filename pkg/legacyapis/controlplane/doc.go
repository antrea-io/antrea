// Copyright 2019 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +k8s:deepcopy-gen=package
// +groupName=controlplane.antrea.tanzu.vmware.com

// Package controlplane contains the latest (or "internal") version of the Antrea
// NetworkPolicy API messages. This is the API messages as represented in memory.
// The contract presented to clients is located in the versioned packages,
// which are sub-directories. The first one is "v1beta1".
// The messages are generated based on the stored NetworkPolicy objects, i.e.
// the objects defined in antrea/pkg/controller/types/networkpolicy.go.
package controlplane
