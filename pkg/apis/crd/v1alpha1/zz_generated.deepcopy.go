//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Advertisements) DeepCopyInto(out *Advertisements) {
	*out = *in
	if in.Service != nil {
		in, out := &in.Service, &out.Service
		*out = new(ServiceAdvertisement)
		(*in).DeepCopyInto(*out)
	}
	if in.Pod != nil {
		in, out := &in.Pod, &out.Pod
		*out = new(PodAdvertisement)
		**out = **in
	}
	if in.Egress != nil {
		in, out := &in.Egress, &out.Egress
		*out = new(EgressAdvertisement)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Advertisements.
func (in *Advertisements) DeepCopy() *Advertisements {
	if in == nil {
		return nil
	}
	out := new(Advertisements)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPPeer) DeepCopyInto(out *BGPPeer) {
	*out = *in
	if in.Port != nil {
		in, out := &in.Port, &out.Port
		*out = new(int32)
		**out = **in
	}
	if in.MultihopTTL != nil {
		in, out := &in.MultihopTTL, &out.MultihopTTL
		*out = new(int32)
		**out = **in
	}
	if in.GracefulRestartTimeSeconds != nil {
		in, out := &in.GracefulRestartTimeSeconds, &out.GracefulRestartTimeSeconds
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPPeer.
func (in *BGPPeer) DeepCopy() *BGPPeer {
	if in == nil {
		return nil
	}
	out := new(BGPPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPPolicy) DeepCopyInto(out *BGPPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPPolicy.
func (in *BGPPolicy) DeepCopy() *BGPPolicy {
	if in == nil {
		return nil
	}
	out := new(BGPPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BGPPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPPolicyList) DeepCopyInto(out *BGPPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]BGPPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPPolicyList.
func (in *BGPPolicyList) DeepCopy() *BGPPolicyList {
	if in == nil {
		return nil
	}
	out := new(BGPPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BGPPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPPolicySpec) DeepCopyInto(out *BGPPolicySpec) {
	*out = *in
	in.NodeSelector.DeepCopyInto(&out.NodeSelector)
	if in.ListenPort != nil {
		in, out := &in.ListenPort, &out.ListenPort
		*out = new(int32)
		**out = **in
	}
	in.Advertisements.DeepCopyInto(&out.Advertisements)
	if in.BGPPeers != nil {
		in, out := &in.BGPPeers, &out.BGPPeers
		*out = make([]BGPPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPPolicySpec.
func (in *BGPPolicySpec) DeepCopy() *BGPPolicySpec {
	if in == nil {
		return nil
	}
	out := new(BGPPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleExternalNodes) DeepCopyInto(out *BundleExternalNodes) {
	*out = *in
	if in.NodeNames != nil {
		in, out := &in.NodeNames, &out.NodeNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleExternalNodes.
func (in *BundleExternalNodes) DeepCopy() *BundleExternalNodes {
	if in == nil {
		return nil
	}
	out := new(BundleExternalNodes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleFileServer) DeepCopyInto(out *BundleFileServer) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleFileServer.
func (in *BundleFileServer) DeepCopy() *BundleFileServer {
	if in == nil {
		return nil
	}
	out := new(BundleFileServer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleNodes) DeepCopyInto(out *BundleNodes) {
	*out = *in
	if in.NodeNames != nil {
		in, out := &in.NodeNames, &out.NodeNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleNodes.
func (in *BundleNodes) DeepCopy() *BundleNodes {
	if in == nil {
		return nil
	}
	out := new(BundleNodes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleServerAuthConfiguration) DeepCopyInto(out *BundleServerAuthConfiguration) {
	*out = *in
	if in.AuthSecret != nil {
		in, out := &in.AuthSecret, &out.AuthSecret
		*out = new(corev1.SecretReference)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleServerAuthConfiguration.
func (in *BundleServerAuthConfiguration) DeepCopy() *BundleServerAuthConfiguration {
	if in == nil {
		return nil
	}
	out := new(BundleServerAuthConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EgressAdvertisement) DeepCopyInto(out *EgressAdvertisement) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EgressAdvertisement.
func (in *EgressAdvertisement) DeepCopy() *EgressAdvertisement {
	if in == nil {
		return nil
	}
	out := new(EgressAdvertisement)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalNode) DeepCopyInto(out *ExternalNode) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalNode.
func (in *ExternalNode) DeepCopy() *ExternalNode {
	if in == nil {
		return nil
	}
	out := new(ExternalNode)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExternalNode) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalNodeList) DeepCopyInto(out *ExternalNodeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ExternalNode, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalNodeList.
func (in *ExternalNodeList) DeepCopy() *ExternalNodeList {
	if in == nil {
		return nil
	}
	out := new(ExternalNodeList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExternalNodeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalNodeSpec) DeepCopyInto(out *ExternalNodeSpec) {
	*out = *in
	if in.Interfaces != nil {
		in, out := &in.Interfaces, &out.Interfaces
		*out = make([]NetworkInterface, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalNodeSpec.
func (in *ExternalNodeSpec) DeepCopy() *ExternalNodeSpec {
	if in == nil {
		return nil
	}
	out := new(ExternalNodeSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HTTPProtocol) DeepCopyInto(out *HTTPProtocol) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HTTPProtocol.
func (in *HTTPProtocol) DeepCopy() *HTTPProtocol {
	if in == nil {
		return nil
	}
	out := new(HTTPProtocol)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPBlock) DeepCopyInto(out *IPBlock) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPBlock.
func (in *IPBlock) DeepCopy() *IPBlock {
	if in == nil {
		return nil
	}
	out := new(IPBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *L7Protocol) DeepCopyInto(out *L7Protocol) {
	*out = *in
	if in.HTTP != nil {
		in, out := &in.HTTP, &out.HTTP
		*out = new(HTTPProtocol)
		**out = **in
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLSProtocol)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new L7Protocol.
func (in *L7Protocol) DeepCopy() *L7Protocol {
	if in == nil {
		return nil
	}
	out := new(L7Protocol)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NamespacedName) DeepCopyInto(out *NamespacedName) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NamespacedName.
func (in *NamespacedName) DeepCopy() *NamespacedName {
	if in == nil {
		return nil
	}
	out := new(NamespacedName)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkInterface) DeepCopyInto(out *NetworkInterface) {
	*out = *in
	if in.IPs != nil {
		in, out := &in.IPs, &out.IPs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkInterface.
func (in *NetworkInterface) DeepCopy() *NetworkInterface {
	if in == nil {
		return nil
	}
	out := new(NetworkInterface)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeLatencyMonitor) DeepCopyInto(out *NodeLatencyMonitor) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeLatencyMonitor.
func (in *NodeLatencyMonitor) DeepCopy() *NodeLatencyMonitor {
	if in == nil {
		return nil
	}
	out := new(NodeLatencyMonitor)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NodeLatencyMonitor) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeLatencyMonitorList) DeepCopyInto(out *NodeLatencyMonitorList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NodeLatencyMonitor, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeLatencyMonitorList.
func (in *NodeLatencyMonitorList) DeepCopy() *NodeLatencyMonitorList {
	if in == nil {
		return nil
	}
	out := new(NodeLatencyMonitorList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NodeLatencyMonitorList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeLatencyMonitorSpec) DeepCopyInto(out *NodeLatencyMonitorSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeLatencyMonitorSpec.
func (in *NodeLatencyMonitorSpec) DeepCopy() *NodeLatencyMonitorSpec {
	if in == nil {
		return nil
	}
	out := new(NodeLatencyMonitorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PodAdvertisement) DeepCopyInto(out *PodAdvertisement) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodAdvertisement.
func (in *PodAdvertisement) DeepCopy() *PodAdvertisement {
	if in == nil {
		return nil
	}
	out := new(PodAdvertisement)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceAdvertisement) DeepCopyInto(out *ServiceAdvertisement) {
	*out = *in
	if in.IPTypes != nil {
		in, out := &in.IPTypes, &out.IPTypes
		*out = make([]ServiceIPType, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceAdvertisement.
func (in *ServiceAdvertisement) DeepCopy() *ServiceAdvertisement {
	if in == nil {
		return nil
	}
	out := new(ServiceAdvertisement)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollection) DeepCopyInto(out *SupportBundleCollection) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollection.
func (in *SupportBundleCollection) DeepCopy() *SupportBundleCollection {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollection)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SupportBundleCollection) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionCondition) DeepCopyInto(out *SupportBundleCollectionCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionCondition.
func (in *SupportBundleCollectionCondition) DeepCopy() *SupportBundleCollectionCondition {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionList) DeepCopyInto(out *SupportBundleCollectionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SupportBundleCollection, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionList.
func (in *SupportBundleCollectionList) DeepCopy() *SupportBundleCollectionList {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SupportBundleCollectionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionSpec) DeepCopyInto(out *SupportBundleCollectionSpec) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = new(BundleNodes)
		(*in).DeepCopyInto(*out)
	}
	if in.ExternalNodes != nil {
		in, out := &in.ExternalNodes, &out.ExternalNodes
		*out = new(BundleExternalNodes)
		(*in).DeepCopyInto(*out)
	}
	out.FileServer = in.FileServer
	in.Authentication.DeepCopyInto(&out.Authentication)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionSpec.
func (in *SupportBundleCollectionSpec) DeepCopy() *SupportBundleCollectionSpec {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionStatus) DeepCopyInto(out *SupportBundleCollectionStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]SupportBundleCollectionCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionStatus.
func (in *SupportBundleCollectionStatus) DeepCopy() *SupportBundleCollectionStatus {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSProtocol) DeepCopyInto(out *TLSProtocol) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSProtocol.
func (in *TLSProtocol) DeepCopy() *TLSProtocol {
	if in == nil {
		return nil
	}
	out := new(TLSProtocol)
	in.DeepCopyInto(out)
	return out
}
