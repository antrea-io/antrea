// +build !ignore_autogenerated

// Copyright 2021 Antrea Authors
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

package stats

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AntreaClusterNetworkPolicyStats) DeepCopyInto(out *AntreaClusterNetworkPolicyStats) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.TrafficStats = in.TrafficStats
	if in.RuleTrafficStats != nil {
		in, out := &in.RuleTrafficStats, &out.RuleTrafficStats
		*out = make([]RuleTrafficStats, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AntreaClusterNetworkPolicyStats.
func (in *AntreaClusterNetworkPolicyStats) DeepCopy() *AntreaClusterNetworkPolicyStats {
	if in == nil {
		return nil
	}
	out := new(AntreaClusterNetworkPolicyStats)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AntreaClusterNetworkPolicyStats) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AntreaClusterNetworkPolicyStatsList) DeepCopyInto(out *AntreaClusterNetworkPolicyStatsList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AntreaClusterNetworkPolicyStats, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AntreaClusterNetworkPolicyStatsList.
func (in *AntreaClusterNetworkPolicyStatsList) DeepCopy() *AntreaClusterNetworkPolicyStatsList {
	if in == nil {
		return nil
	}
	out := new(AntreaClusterNetworkPolicyStatsList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AntreaClusterNetworkPolicyStatsList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AntreaNetworkPolicyStats) DeepCopyInto(out *AntreaNetworkPolicyStats) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.TrafficStats = in.TrafficStats
	if in.RuleTrafficStats != nil {
		in, out := &in.RuleTrafficStats, &out.RuleTrafficStats
		*out = make([]RuleTrafficStats, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AntreaNetworkPolicyStats.
func (in *AntreaNetworkPolicyStats) DeepCopy() *AntreaNetworkPolicyStats {
	if in == nil {
		return nil
	}
	out := new(AntreaNetworkPolicyStats)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AntreaNetworkPolicyStats) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AntreaNetworkPolicyStatsList) DeepCopyInto(out *AntreaNetworkPolicyStatsList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AntreaNetworkPolicyStats, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AntreaNetworkPolicyStatsList.
func (in *AntreaNetworkPolicyStatsList) DeepCopy() *AntreaNetworkPolicyStatsList {
	if in == nil {
		return nil
	}
	out := new(AntreaNetworkPolicyStatsList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AntreaNetworkPolicyStatsList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkPolicyStats) DeepCopyInto(out *NetworkPolicyStats) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.TrafficStats = in.TrafficStats
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkPolicyStats.
func (in *NetworkPolicyStats) DeepCopy() *NetworkPolicyStats {
	if in == nil {
		return nil
	}
	out := new(NetworkPolicyStats)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NetworkPolicyStats) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkPolicyStatsList) DeepCopyInto(out *NetworkPolicyStatsList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NetworkPolicyStats, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkPolicyStatsList.
func (in *NetworkPolicyStatsList) DeepCopy() *NetworkPolicyStatsList {
	if in == nil {
		return nil
	}
	out := new(NetworkPolicyStatsList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NetworkPolicyStatsList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuleTrafficStats) DeepCopyInto(out *RuleTrafficStats) {
	*out = *in
	out.TrafficStats = in.TrafficStats
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuleTrafficStats.
func (in *RuleTrafficStats) DeepCopy() *RuleTrafficStats {
	if in == nil {
		return nil
	}
	out := new(RuleTrafficStats)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TrafficStats) DeepCopyInto(out *TrafficStats) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TrafficStats.
func (in *TrafficStats) DeepCopy() *TrafficStats {
	if in == nil {
		return nil
	}
	out := new(TrafficStats)
	in.DeepCopyInto(out)
	return out
}
