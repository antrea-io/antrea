// Copyright 2023 Antrea Authors
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

package types

import (
	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

// ServiceGroupInfo is used in AntreaProxy for Multi-cluster Service load-balancing.
// It stores a local exported Service's GroupID and its ClusterIP.
type ServiceGroupInfo struct {
	// GroupID of an exported Service.
	GroupID binding.GroupIDType
	// ClusterIP info of an exported Service.
	Endpoint k8sproxy.Endpoint
}
