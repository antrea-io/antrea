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
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

const (
	serviceName = "antrea"
)

var _ ControllerQuerier = new(controllerQuerier)

//TODO: expand this interface similarly to AgentQuerier
type ControllerQuerier interface {
	GetControllerInfo(controllInfo *v1beta1.AntreaControllerInfo, partial bool)
	QueryNetworkPolicies(namespace string, podName string) (applied []antreatypes.NetworkPolicy,
		egress []antreatypes.NetworkPolicy, ingress []antreatypes.NetworkPolicy)
}

//TODO: implement interface methods
type controllerQuerier struct {
	networkPolicyInfoQuerier querier.ControllerNetworkPolicyInfoQuerier
	internalNetworkPolicyStore storage.Interface
	appliedToGroupStore storage.Interface
	apiPort                  int
}

func NewControllerQuerier(networkPolicyInfoQuerier querier.ControllerNetworkPolicyInfoQuerier,
	internalNetworkPolicyStore storage.Interface, appliedToGroupStore storage.Interface,
	apiPort int) *controllerQuerier {
	return &controllerQuerier{networkPolicyInfoQuerier: networkPolicyInfoQuerier,
		internalNetworkPolicyStore: internalNetworkPolicyStore, appliedToGroupStore: appliedToGroupStore,
		apiPort: apiPort}
}

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
		controllInfo.APIPort = cq.apiPort
	}
}

//Query functions
func (cq controllerQuerier) QueryNetworkPolicies(namespace string, podName string) (applied []antreatypes.NetworkPolicy,
	egress []antreatypes.NetworkPolicy, ingress []antreatypes.NetworkPolicy) {
	// grab list of all policies from internalNetworkPolicyStore
	internalPolicies := cq.internalNetworkPolicyStore.List()
	// create network policies categories
	applied, egress, ingress = make([]antreatypes.NetworkPolicy, 0), make([]antreatypes.NetworkPolicy, 0),
		make([]antreatypes.NetworkPolicy, 0)
	// filter all policies into appropriate groups
	for _, policy := range internalPolicies {
		for _, key := range policy.(*antreatypes.NetworkPolicy).AppliedToGroups {
			// Check if policy is applied to endpoint
			//TODO: what is this boolean. what is this error?
			appliedToGroupInterface, _, _ := cq.appliedToGroupStore.Get(key)
			appliedToGroup := appliedToGroupInterface.(*antreatypes.AppliedToGroup)
			// if appliedToGroup selects pod in namespace, append policy to applied category
			for _, podSet := range appliedToGroup.PodsByNode {
				for _, member := range podSet {
					trialPodName, trialNamespace := member.Pod.Name, member.Pod.Namespace
					if podName == trialPodName && namespace == trialNamespace {
						applied = append(applied, *policy.(*antreatypes.NetworkPolicy))
					}
				}
			}
			// Check if policy defines an egress or ingress rule on endpoint
			for _, rule := range policy.(*antreatypes.NetworkPolicy).Rules {
				//TODO: figure out how to see if namespace, pod correlates with NetworkPolicyPeer
				_, _ = rule.From, rule.To
			}
		}
	}

	return
}
