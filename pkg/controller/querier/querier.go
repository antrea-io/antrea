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

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/querier"
)

const (
	serviceName = "antrea"
)

var _ ControllerQuerier = new(controllerQuerier)

type ControllerQuerier interface {
	GetControllerInfo(controllerInfo *v1beta1.AntreaControllerInfo, partial bool)
}

type controllerQuerier struct {
	networkPolicyInfoQuerier querier.ControllerNetworkPolicyInfoQuerier
	apiPort                  int
}

func NewControllerQuerier(networkPolicyInfoQuerier querier.ControllerNetworkPolicyInfoQuerier, apiPort int) *controllerQuerier {
	return &controllerQuerier{networkPolicyInfoQuerier: networkPolicyInfoQuerier, apiPort: apiPort}
}

// getNetworkPolicyInfoQuerier gets current network policy info querier.
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
func (cq controllerQuerier) GetControllerInfo(controllerInfo *v1beta1.AntreaControllerInfo, partial bool) {
	controllerInfo.NetworkPolicyControllerInfo = cq.getNetworkPolicyControllerInfo()
	controllerInfo.ConnectedAgentNum = int32(cq.getNetworkPolicyInfoQuerier().GetConnectedAgentNum())
	controllerInfo.ControllerConditions = cq.getControllerConditions()

	if !partial {
		controllerInfo.Version = querier.GetVersion()
		controllerInfo.PodRef = querier.GetSelfPod()
		controllerInfo.NodeRef = querier.GetSelfNode(false, "")
		controllerInfo.ServiceRef = cq.getService()
		controllerInfo.APIPort = cq.apiPort
	}
}
