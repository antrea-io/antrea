// Copyright 2024 Antrea Authors
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

package apis

import (
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/util/printers"
)

// AntreaAgentInfoResponse is the struct for the response of agentinfo command.
// It includes all fields except meta info from v1beta1.AntreaAgentInfo struct.
type AntreaAgentInfoResponse struct {
	Version                     string                              `json:"version,omitempty"`                     // Antrea binary version
	PodRef                      corev1.ObjectReference              `json:"podRef,omitempty"`                      // The Pod that Antrea Agent is running in
	NodeRef                     corev1.ObjectReference              `json:"nodeRef,omitempty"`                     // The Node that Antrea Agent is running in
	NodeSubnets                 []string                            `json:"nodeSubnets,omitempty"`                 // Node subnets
	OVSInfo                     v1beta1.OVSInfo                     `json:"ovsInfo,omitempty"`                     // OVS Information
	NetworkPolicyControllerInfo v1beta1.NetworkPolicyControllerInfo `json:"networkPolicyControllerInfo,omitempty"` // Antrea Agent NetworkPolicy information
	LocalPodNum                 int32                               `json:"localPodNum,omitempty"`                 // The number of Pods which the agent is in charge of
	AgentConditions             []v1beta1.AgentCondition            `json:"agentConditions,omitempty"`             // Agent condition contains types like AgentHealthy
}

func (r AntreaAgentInfoResponse) GetTableHeader() []string {
	return []string{"POD", "NODE", "STATUS", "NODE-SUBNET", "NETWORK-POLICIES", "ADDRESS-GROUPS", "APPLIED-TO-GROUPS", "LOCAL-PODS"}
}

func (r AntreaAgentInfoResponse) getAgentConditionStr() string {
	if r.AgentConditions == nil {
		return ""
	}
	agentCondition := "Healthy"
	for _, cond := range r.AgentConditions {
		if cond.Status == corev1.ConditionUnknown {
			agentCondition = "Unknown"
		}
		if cond.Status == corev1.ConditionFalse {
			return "Unhealthy"
		}
	}
	return agentCondition
}

func (r AntreaAgentInfoResponse) GetTableRow(maxColumnLength int) []string {
	return []string{r.PodRef.Namespace + "/" + r.PodRef.Name,
		r.NodeRef.Name,
		r.getAgentConditionStr(),
		printers.GenerateTableElementWithSummary(r.NodeSubnets, maxColumnLength),
		strconv.Itoa(int(r.NetworkPolicyControllerInfo.NetworkPolicyNum)),
		strconv.Itoa(int(r.NetworkPolicyControllerInfo.AddressGroupNum)),
		strconv.Itoa(int(r.NetworkPolicyControllerInfo.AppliedToGroupNum)),
		strconv.Itoa(int(r.LocalPodNum))}
}

func (r AntreaAgentInfoResponse) SortRows() bool {
	return true
}

type FQDNCacheResponse struct {
	FQDNName       string    `json:"fqdnName,omitempty"`
	IPAddress      string    `json:"ipAddress,omitempty"`
	ExpirationTime time.Time `json:"expirationTime,omitempty"`
}

func (r FQDNCacheResponse) GetTableHeader() []string {
	return []string{"FQDN", "ADDRESS", "EXPIRATION TIME"}
}

func (r FQDNCacheResponse) GetTableRow(maxColumn int) []string {
	return []string{
		r.FQDNName,
		r.IPAddress,
		r.ExpirationTime.String(),
	}
}

func (r FQDNCacheResponse) SortRows() bool {
	return true
}

type FeatureGateResponse struct {
	Component string `json:"component,omitempty"`
	Name      string `json:"name,omitempty"`
	Status    string `json:"status,omitempty"`
	Version   string `json:"version,omitempty"`
}

// MemberlistResponse describes the response struct of memberlist command.
type MemberlistResponse struct {
	NodeName string `json:"nodeName,omitempty"`
	IP       string `json:"ip,omitempty"`
	Status   string `json:"status,omitempty"`
}

func (r MemberlistResponse) GetTableHeader() []string {
	return []string{"NODE", "IP", "STATUS"}
}

func (r MemberlistResponse) GetTableRow(_ int) []string {
	return []string{r.NodeName, r.IP, r.Status}
}

func (r MemberlistResponse) SortRows() bool {
	return true
}

type MulticastResponse struct {
	PodName      string `json:"name,omitempty" antctl:"name,Name of the Pod"`
	PodNamespace string `json:"podNamespace,omitempty"`
	Inbound      string `json:"inbound,omitempty"`
	Outbound     string `json:"outbound,omitempty"`
}

func (r MulticastResponse) GetTableHeader() []string {
	return []string{"NAMESPACE", "NAME", "INBOUND", "OUTBOUND"}
}

func (r MulticastResponse) GetTableRow(_ int) []string {
	return []string{r.PodNamespace, r.PodName, r.Inbound, r.Outbound}
}

func (r MulticastResponse) SortRows() bool {
	return true
}

// OVSFlowResponse is the response struct of ovsflows command.
type OVSFlowResponse struct {
	Flow string `json:"flow,omitempty"`
}

func (r OVSFlowResponse) GetTableHeader() []string {
	return []string{""}
}

func (r OVSFlowResponse) GetTableRow(maxColumnLength int) []string {
	return []string{r.Flow}
}

func (r OVSFlowResponse) SortRows() bool {
	return false
}

// OVSTracingResponse is the response struct of ovstracing command.
type OVSTracingResponse struct {
	Result string `json:"result,omitempty"`
}

// PodInterfaceResponse describes the response struct of pod-interface command.
type PodInterfaceResponse struct {
	PodName       string   `json:"name,omitempty" antctl:"name,Name of the Pod"`
	PodNamespace  string   `json:"podNamespace,omitempty"`
	InterfaceName string   `json:"interfaceName,omitempty"`
	IPs           []string `json:"ips,omitempty"`
	MAC           string   `json:"mac,omitempty"`
	PortUUID      string   `json:"portUUID,omitempty"`
	OFPort        int32    `json:"ofPort,omitempty"`
	ContainerID   string   `json:"containerID,omitempty"`
}

func (r PodInterfaceResponse) GetTableHeader() []string {
	return []string{"NAMESPACE", "NAME", "INTERFACE-NAME", "IP", "MAC", "PORT-UUID", "OF-PORT", "CONTAINER-ID"}
}

func (r PodInterfaceResponse) getContainerIDStr() string {
	if len(r.ContainerID) > 12 {
		return r.ContainerID[0:11]
	}
	return r.ContainerID
}

func (r PodInterfaceResponse) GetTableRow(_ int) []string {
	return []string{r.PodNamespace, r.PodName, r.InterfaceName, strings.Join(r.IPs, ", "), r.MAC, r.PortUUID, strconv.Itoa(int(r.OFPort)), r.getContainerIDStr()}
}

func (r PodInterfaceResponse) SortRows() bool {
	return true
}

// ServiceExternalIPInfo contains the essential information for Services with type of Loadbalancer managed by Antrea.
type ServiceExternalIPInfo struct {
	ServiceName    string `json:"serviceName,omitempty" antctl:"name,Name of the Service"`
	Namespace      string `json:"namespace,omitempty"`
	ExternalIP     string `json:"externalIP,omitempty"`
	ExternalIPPool string `json:"externalIPPool,omitempty"`
	AssignedNode   string `json:"assignedNode,omitempty"`
}

func (r ServiceExternalIPInfo) GetTableHeader() []string {
	return []string{"NAMESPACE", "NAME", "EXTERNAL-IP-POOL", "EXTERNAL-IP", "ASSIGNED-NODE"}
}

func (r ServiceExternalIPInfo) GetTableRow(_ int) []string {
	return []string{r.Namespace, r.ServiceName, r.ExternalIPPool, r.ExternalIP, r.AssignedNode}
}

func (r ServiceExternalIPInfo) SortRows() bool {
	return true
}

// BGPPolicyResponse describes the response struct of bgppolicy command.
type BGPPolicyResponse struct {
	BGPPolicyName           string `json:"name,omitempty"`
	RouterID                string `json:"routerID,omitempty"`
	LocalASN                int32  `json:"localASN,omitempty"`
	ListenPort              int32  `json:"listenPort,omitempty"`
	ConfederationIdentifier int32  `json:"confederationIdentifier,omitempty"`
}

func (r BGPPolicyResponse) GetTableHeader() []string {
	return []string{"NAME", "ROUTER-ID", "LOCAL-ASN", "LISTEN-PORT", "CONFEDERATION-IDENTIFIER"}
}

func (r BGPPolicyResponse) GetTableRow(_ int) []string {
	return []string{r.BGPPolicyName, r.RouterID, strconv.Itoa(int(r.LocalASN)), strconv.Itoa(int(r.ListenPort)), strconv.Itoa(int(r.ConfederationIdentifier))}
}

func (r BGPPolicyResponse) SortRows() bool {
	return true
}

// BGPPeerResponse describes the response struct of bgppeers command.
type BGPPeerResponse struct {
	Peer  string `json:"peer,omitempty"`
	ASN   int32  `json:"asn,omitempty"`
	State string `json:"state,omitempty"`
}

func (r BGPPeerResponse) GetTableHeader() []string {
	return []string{"PEER", "ASN", "STATE"}
}

func (r BGPPeerResponse) GetTableRow(_ int) []string {
	return []string{r.Peer, strconv.Itoa(int(r.ASN)), r.State}
}

func (r BGPPeerResponse) SortRows() bool {
	return true
}

// BGPRouteResponse describes the response struct of bgproutes command.
type BGPRouteResponse struct {
	Route     string `json:"route,omitempty"`
	Type      string `json:"type,omitempty"`
	K8sObjRef string `json:"k8sObjRef,omitempty"`
}

func (r BGPRouteResponse) GetTableHeader() []string {
	return []string{"ROUTE", "TYPE", "K8S-OBJ-REF"}
}

func (r BGPRouteResponse) GetTableRow(_ int) []string {
	return []string{r.Route, r.Type, r.K8sObjRef}
}

func (r BGPRouteResponse) SortRows() bool {
	return true
}
