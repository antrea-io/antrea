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

package v1alpha2

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalEntity struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Desired state of the external entity.
	Spec ExternalEntitySpec `json:"spec,omitempty"`
}

// ExternalEntitySpec defines the desired state for ExternalEntity.
type ExternalEntitySpec struct {
	// Endpoints is a list of external endpoints associated with this entity.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// Ports maintain the list of named ports.
	Ports []NamedPort `json:"ports,omitempty"`
	// ExternalNode is the opaque identifier of the agent/controller responsible
	// for additional processing or handling of this external entity.
	ExternalNode string `json:"externalNode,omitempty"`
}

// Endpoint refers to an endpoint associated with the ExternalEntity.
type Endpoint struct {
	// IP associated with this endpoint.
	IP string `json:"ip,omitempty"`
	// Name identifies this endpoint. Could be the network interface name in case of VMs.
	// +optional
	Name string `json:"name,omitempty"`
}

// NamedPort describes the port and protocol to match in a rule.
type NamedPort struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	Protocol v1.Protocol `json:"protocol,omitempty"`
	// The port on the given protocol.
	// +optional
	Port int32 `json:"port,omitempty"`
	// Name associated with the Port.
	// +optional
	Name string `json:"name,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalEntityList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExternalEntity `json:"items,omitempty"`
}

// AppliedTo selects the entities to which a policy is applied.
type AppliedTo struct {
	// Select Pods matched by this selector. If set with NamespaceSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector;
	// otherwise, Pods are matched from all Namespaces.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector. If set with
	// PodSelector, Pods are matched from Namespaces matched by the
	// NamespaceSelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// Groups is the set of ClusterGroup names.
	// +optional
	Groups []string `json:"groups,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Egress defines which egress (SNAT) IP the traffic from the selected Pods to
// the external network should use.
type Egress struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of Egress.
	Spec EgressSpec `json:"spec"`

	// EgressStatus represents the current status of an Egress.
	Status EgressStatus `json:"status"`
}

// EgressStatus represents the current status of an Egress.
type EgressStatus struct {
	// The name of the Node that holds the Egress IP.
	EgressNode string `json:"egressNode"`
	// EgressIP indicates the effective Egress IP for the selected workloads. It could be empty if the Egress IP in spec
	// is not assigned to any Node. It's also useful when there are more than one Egress IP specified in spec.
	EgressIP string `json:"egressIP"`

	Conditions []EgressCondition `json:"conditions,omitempty"`
}

type EgressConditionType string

const (
	// IPAllocated means at least one IP has been allocated to the Egress from ExternalIPPool.
	// It is not applicable for Egresses with empty ExternalIPPool.
	IPAllocated EgressConditionType = "IPAllocated"
	// IPAssigned means the Egress has been assigned to a Node.
	// It is not applicable for Egresses with empty ExternalIPPool.
	IPAssigned EgressConditionType = "IPAssigned"
)

type EgressCondition struct {
	Type               EgressConditionType `json:"type"`
	Status             v1.ConditionStatus  `json:"status"`
	LastTransitionTime metav1.Time         `json:"lastTransitionTime"`
	Reason             string              `json:"reason,omitempty"`
	Message            string              `json:"message,omitempty"`
}

// EgressSpec defines the desired state for Egress.
type EgressSpec struct {
	// AppliedTo selects Pods to which the Egress will be applied.
	AppliedTo AppliedTo `json:"appliedTo"`
	// EgressIP specifies the SNAT IP address for the selected workloads.
	// If ExternalIPPool is empty, it must be specified manually.
	// If ExternalIPPool is non-empty, it can be empty and will be assigned by Antrea automatically.
	// If both ExternalIPPool and EgressIP are non-empty, the IP must be in the pool.
	EgressIP string `json:"egressIP,omitempty"`
	// EgressIPs specifies multiple SNAT IP addresses for the selected workloads.
	// Cannot be set with EgressIP.
	EgressIPs []string `json:"egressIPs,omitempty"`
	// ExternalIPPool specifies the IP Pool that the EgressIP should be allocated from.
	// If it is empty, the specified EgressIP must be assigned to a Node manually.
	// If it is non-empty, the EgressIP will be assigned to a Node specified by the pool automatically and will failover
	// to a different Node when the Node becomes unreachable.
	ExternalIPPool string `json:"externalIPPool,omitempty"`
	// ExternalIPPools specifies multiple unique IP Pools that the EgressIPs should be allocated from. Entries with the
	// same index in EgressIPs and ExternalIPPools are correlated.
	// Cannot be set with ExternalIPPool.
	ExternalIPPools []string `json:"externalIPPools,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Egress `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalIPPool defines one or multiple IP sets that can be used in the external network. For instance, the IPs can be
// allocated to the Egress resources as the Egress IPs.
type ExternalIPPool struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the ExternalIPPool.
	Spec ExternalIPPoolSpec `json:"spec"`

	// The current status of the ExternalIPPool.
	Status ExternalIPPoolStatus `json:"status"`
}

type ExternalIPPoolSpec struct {
	// The IP ranges of this IP pool, e.g. 10.10.0.0/24, 10.10.10.2-10.10.10.20, 10.10.10.30-10.10.10.30.
	IPRanges []IPRange `json:"ipRanges"`
	// The Nodes that the external IPs can be assigned to. If empty, it means all Nodes.
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`
}

// IPRange is a set of contiguous IP addresses, represented by a CIDR or a pair of start and end IPs.
type IPRange struct {
	// The CIDR of this range, e.g. 10.10.10.0/24.
	CIDR string `json:"cidr,omitempty"`
	// The start IP of the range, e.g. 10.10.20.5, inclusive.
	Start string `json:"start,omitempty"`
	// The end IP of the range, e.g. 10.10.20.20, inclusive.
	End string `json:"end,omitempty"`
}

type ExternalIPPoolStatus struct {
	Usage IPPoolUsage `json:"usage,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExternalIPPool `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPPool defines one or multiple IP sets that can be used for flexible IPAM feature. For instance, the IPs can be
// allocated to Pods according to IP pool specified in Deployment annotation.
type IPPool struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the IPPool.
	Spec IPPoolSpec `json:"spec"`

	// Most recently observed status of the pool.
	Status IPPoolStatus `json:"status"`
}

type IPVersion int

const (
	IPv4 = IPVersion(4)
	IPv6 = IPVersion(6)
)

type IPPoolSpec struct {
	// IP Version for this IP pool - either 4 or 6
	IPVersion IPVersion `json:"ipVersion"`
	// List IP ranges, along with subnet definition.
	IPRanges []SubnetIPRange `json:"ipRanges"`
}

// SubnetInfo specifies subnet attributes for IP Range
type SubnetInfo struct {
	// Gateway IP for this subnet, eg. 10.10.1.1
	Gateway string `json:"gateway"`
	// Prefix length for the subnet, eg. 24
	PrefixLength int32 `json:"prefixLength"`
	// VLAN ID for this subnet. Default is 0. Valid value is 0~4094.
	VLAN uint16 `json:"vlan,omitempty"`
}

// SubnetIPRange is a set of contiguous IP addresses, represented by a CIDR or a pair of start and end IPs,
// along with subnet definition.
type SubnetIPRange struct {
	IPRange    `json:",inline"`
	SubnetInfo `json:",inline"`
}

type IPPoolStatus struct {
	IPAddresses []IPAddressState `json:"ipAddresses,omitempty"`
	Usage       IPPoolUsage      `json:"usage,omitempty"`
}

type IPPoolUsage struct {
	// Total number of IPs.
	Total int `json:"total"`
	// Number of allocated IPs.
	Used int `json:"used"`
}
type IPAddressPhase string

const (
	IPAddressPhaseAllocated    IPAddressPhase = "Allocated"
	IPAddressPhasePreallocated IPAddressPhase = "Preallocated"
	IPAddressPhaseReserved     IPAddressPhase = "Reserved"
)

type IPAddressState struct {
	// IP Address this entry is tracking
	IPAddress string `json:"ipAddress"`
	// Allocation state - either Allocated or Preallocated
	Phase IPAddressPhase `json:"phase"`
	// Owner this IP Address is allocated to
	Owner IPAddressOwner `json:"owner"`
	// TODO: add usage statistics (consistent with ExternalIPPool status)
}

type IPAddressOwner struct {
	Pod         *PodOwner         `json:"pod,omitempty"`
	StatefulSet *StatefulSetOwner `json:"statefulSet,omitempty"`
}

// Pod owner
type PodOwner struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	ContainerID string `json:"containerID"`
	// Network interface name. Used when the IP is allocated for a secondary network interface
	// of the Pod.
	IFName string `json:"ifName,omitempty"`
}

// StatefulSet owner
type StatefulSetOwner struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Index     int    `json:"index"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IPPool `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TrafficControl allows mirroring or redirecting the traffic Pods send or receive. It enables users to monitor and
// analyze Pod traffic, and to enforce custom network protections for Pods with fine-grained control over network
// traffic.
type TrafficControl struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of TrafficControl.
	Spec TrafficControlSpec `json:"spec"`
}

type TrafficControlSpec struct {
	// AppliedTo selects Pods to which the traffic control configuration will be applied.
	AppliedTo AppliedTo `json:"appliedTo"`

	// The direction of traffic that should be matched. It can be Ingress, Egress, or Both.
	Direction Direction `json:"direction"`

	// The action that should be taken for the traffic. It can be Redirect or Mirror.
	Action TrafficControlAction `json:"action"`

	// The port to which the traffic should be redirected or mirrored.
	TargetPort TrafficControlPort `json:"targetPort"`

	// The port from which the traffic will be sent back to OVS. It should only be set for Redirect action.
	ReturnPort *TrafficControlPort `json:"returnPort,omitempty"`
}

type Direction string

const (
	DirectionIngress Direction = "Ingress"
	DirectionEgress  Direction = "Egress"
	DirectionBoth    Direction = "Both"
)

type TrafficControlAction string

const (
	ActionRedirect TrafficControlAction = "Redirect"
	ActionMirror   TrafficControlAction = "Mirror"
)

// TrafficControlPort represents a port that can be used as the target of traffic mirroring or redirecting, and the
// return port of traffic redirecting.
type TrafficControlPort struct {
	// OVSInternal represents an OVS internal port.
	OVSInternal *OVSInternalPort `json:"ovsInternal,omitempty"`
	// Device represents a network device.
	Device *NetworkDevice `json:"device,omitempty"`
	// GENEVE represents a GENEVE tunnel.
	GENEVE *UDPTunnel `json:"geneve,omitempty"`
	// VXLAN represents a VXLAN tunnel.
	VXLAN *UDPTunnel `json:"vxlan,omitempty"`
	// GRE represents a GRE tunnel.
	GRE *GRETunnel `json:"gre,omitempty"`
	// ERSPAN represents a ERSPAN tunnel.
	ERSPAN *ERSPANTunnel `json:"erspan,omitempty"`
}

// OVSInternalPort represents an OVS internal port. Antrea will create the port if it doesn't exist.
type OVSInternalPort struct {
	// The name of the OVS internal port.
	Name string `json:"name"`
}

// NetworkDevice represents a network device. It must exist on all Nodes. Antrea will attach it to the OVS bridge if it
// is not attached.
type NetworkDevice struct {
	// The name of the network device.
	Name string `json:"name"`
}

// UDPTunnel represents a UDP based tunnel. Antrea will create a port on the OVS bridge for the tunnel.
type UDPTunnel struct {
	// The remote IP of the tunnel.
	RemoteIP string `json:"remoteIP"`
	// The ID of the tunnel.
	VNI *int32 `json:"vni,omitempty"`
	// The transport layer destination port of the tunnel. If not specified, the assigned IANA port will be used, i.e.,
	// 4789 for VXLAN, 6081 for GENEVE.
	DestinationPort *int32 `json:"destinationPort,omitempty"`
}

// GRETunnel represents a GRE tunnel. Antrea will create a port on the OVS bridge for the tunnel.
type GRETunnel struct {
	// The remote IP of the tunnel.
	RemoteIP string `json:"remoteIP"`
	// GRE key.
	Key *int32 `json:"key,omitempty"`
}

// ERSPANTunnel represents an ERSPAN tunnel. Antrea will create a port on the OVS bridge for the tunnel.
type ERSPANTunnel struct {
	// The remote IP of the tunnel.
	RemoteIP string `json:"remoteIP"`
	// ERSPAN session ID.
	SessionID *int32 `json:"sessionID,omitempty"`
	// ERSPAN version.
	Version int32 `json:"version"`
	// ERSPAN Index.
	Index *int32 `json:"index,omitempty"`
	// ERSPAN v2 mirrored traffic’s direction.
	Dir *int32 `json:"dir,omitempty"`
	// ERSPAN hardware ID.
	HardwareID *int32 `json:"hardwareID,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TrafficControlList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []TrafficControl `json:"items"`
}
