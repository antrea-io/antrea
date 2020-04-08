// Copyright 2020 Antrea Authors
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

package querier

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

const (
	serviceName = "antrea"
)

var _ ControllerQuerier = new(controllerQuerier)

type ControllerQuerier interface {
	GetControllerInfo(controllInfo *v1beta1.AntreaControllerInfo, partial bool)
}

type controllerQuerier struct {
	networkPolicyInfoQuerier querier.ControllerNetworkPolicyInfoQuerier
}

func NewControllerQuerier(networkPolicyInfoQuerier querier.ControllerNetworkPolicyInfoQuerier) *controllerQuerier {
	return &controllerQuerier{networkPolicyInfoQuerier: networkPolicyInfoQuerier}
}

// GetNodeSubnet gets current network policy info querier.
func (cq controllerQuerier) getNetworkPolicyInfoQuerier() querier.ControllerNetworkPolicyInfoQuerier {
	return cq.networkPolicyInfoQuerier
}

// getService gets current service.
func (cq controllerQuerier) getService() v1.ObjectReference {
	return v1.ObjectReference{Kind: "Service", Name: serviceName}
}

// getNetworkPolicyControllerInfo gets current network policy controller info
// including: number of network policies, address groups and applied to groups.
func (cq controllerQuerier) getNetworkPolicyControllerInfo() v1beta1.NetworkPolicyControllerInfo {
	return v1beta1.NetworkPolicyControllerInfo{
		NetworkPolicyNum:  int32(cq.networkPolicyInfoQuerier.GetNetworkPolicyNum()),
		AddressGroupNum:   int32(cq.networkPolicyInfoQuerier.GetAddressGroupNum()),
		AppliedToGroupNum: int32(cq.networkPolicyInfoQuerier.GetAppliedToGroupNum()),
	}
}

func (cq controllerQuerier) getControllerConditions() []v1beta1.ControllerCondition {
	return []v1beta1.ControllerCondition{
		{
			Type:              v1beta1.ControllerHealthy,
			Status:            v1.ConditionTrue,
			LastHeartbeatTime: metav1.Now(),
		},
	}
}

// GetControllerInfo gets current info of controller.
func (cq controllerQuerier) GetControllerInfo(controllInfo *v1beta1.AntreaControllerInfo, partial bool) {
	controllInfo.NetworkPolicyControllerInfo = cq.getNetworkPolicyControllerInfo()
	controllInfo.ConnectedAgentNum = int32(cq.getNetworkPolicyInfoQuerier().GetConnectedAgentNum())
	controllInfo.ControllerConditions = cq.getControllerConditions()

	if !partial {
		controllInfo.Version = querier.GetVersion()
		controllInfo.PodRef = querier.GetSelfPod()
		controllInfo.NodeRef = querier.GetSelfNode(false, "")
		controllInfo.ServiceRef = cq.getService()
	}
}
