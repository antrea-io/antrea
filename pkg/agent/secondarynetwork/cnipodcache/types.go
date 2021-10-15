// Copyright 2021 Antrea Authors
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

package cnipodcache

type CNIConfigInfo struct {
	CNIVersion     string
	PodName        string
	PodNameSpace   string
	ContainerID    string
	ContainerNetNS string
	MTU            int
	PodCNIDeleted  bool
	// Uses interface name as a key and the network/CNI config (obtained from network-attachment-definition) as value.
	// NOTE: Interface specific network/CNI config required to be maintained for IPAM clean-up needs.
	NetworkConfig map[string][]byte
}

type CNIPodInfoStore interface {
	AddCNIConfigInfo(cniConfig *CNIConfigInfo)
	DeleteCNIConfigInfo(cniConfig *CNIConfigInfo)
	GetValidCNIConfigInfoPerPod(podName, podNamespace string) *CNIConfigInfo
	GetAllCNIConfigInfoPerPod(podName, podNamespace string) []*CNIConfigInfo
	GetCNIConfigInfoByContainerID(podName, podNamespace, containerID string) *CNIConfigInfo
	SetPodCNIDeleted(CNIConfig *CNIConfigInfo)
}
