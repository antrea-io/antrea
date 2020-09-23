// +build !ignore_autogenerated

// Copyright 2020 Antrea Authors
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

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	metrics "github.com/vmware-tanzu/antrea/pkg/apis/metrics"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*AntreaClusterNetworkPolicyMetrics)(nil), (*metrics.AntreaClusterNetworkPolicyMetrics)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AntreaClusterNetworkPolicyMetrics_To_metrics_AntreaClusterNetworkPolicyMetrics(a.(*AntreaClusterNetworkPolicyMetrics), b.(*metrics.AntreaClusterNetworkPolicyMetrics), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*metrics.AntreaClusterNetworkPolicyMetrics)(nil), (*AntreaClusterNetworkPolicyMetrics)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_metrics_AntreaClusterNetworkPolicyMetrics_To_v1alpha1_AntreaClusterNetworkPolicyMetrics(a.(*metrics.AntreaClusterNetworkPolicyMetrics), b.(*AntreaClusterNetworkPolicyMetrics), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*AntreaClusterNetworkPolicyMetricsList)(nil), (*metrics.AntreaClusterNetworkPolicyMetricsList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AntreaClusterNetworkPolicyMetricsList_To_metrics_AntreaClusterNetworkPolicyMetricsList(a.(*AntreaClusterNetworkPolicyMetricsList), b.(*metrics.AntreaClusterNetworkPolicyMetricsList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*metrics.AntreaClusterNetworkPolicyMetricsList)(nil), (*AntreaClusterNetworkPolicyMetricsList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_metrics_AntreaClusterNetworkPolicyMetricsList_To_v1alpha1_AntreaClusterNetworkPolicyMetricsList(a.(*metrics.AntreaClusterNetworkPolicyMetricsList), b.(*AntreaClusterNetworkPolicyMetricsList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*AntreaNetworkPolicyMetrics)(nil), (*metrics.AntreaNetworkPolicyMetrics)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AntreaNetworkPolicyMetrics_To_metrics_AntreaNetworkPolicyMetrics(a.(*AntreaNetworkPolicyMetrics), b.(*metrics.AntreaNetworkPolicyMetrics), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*metrics.AntreaNetworkPolicyMetrics)(nil), (*AntreaNetworkPolicyMetrics)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_metrics_AntreaNetworkPolicyMetrics_To_v1alpha1_AntreaNetworkPolicyMetrics(a.(*metrics.AntreaNetworkPolicyMetrics), b.(*AntreaNetworkPolicyMetrics), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*AntreaNetworkPolicyMetricsList)(nil), (*metrics.AntreaNetworkPolicyMetricsList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AntreaNetworkPolicyMetricsList_To_metrics_AntreaNetworkPolicyMetricsList(a.(*AntreaNetworkPolicyMetricsList), b.(*metrics.AntreaNetworkPolicyMetricsList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*metrics.AntreaNetworkPolicyMetricsList)(nil), (*AntreaNetworkPolicyMetricsList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_metrics_AntreaNetworkPolicyMetricsList_To_v1alpha1_AntreaNetworkPolicyMetricsList(a.(*metrics.AntreaNetworkPolicyMetricsList), b.(*AntreaNetworkPolicyMetricsList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*NetworkPolicyMetrics)(nil), (*metrics.NetworkPolicyMetrics)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_NetworkPolicyMetrics_To_metrics_NetworkPolicyMetrics(a.(*NetworkPolicyMetrics), b.(*metrics.NetworkPolicyMetrics), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*metrics.NetworkPolicyMetrics)(nil), (*NetworkPolicyMetrics)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_metrics_NetworkPolicyMetrics_To_v1alpha1_NetworkPolicyMetrics(a.(*metrics.NetworkPolicyMetrics), b.(*NetworkPolicyMetrics), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*NetworkPolicyMetricsList)(nil), (*metrics.NetworkPolicyMetricsList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_NetworkPolicyMetricsList_To_metrics_NetworkPolicyMetricsList(a.(*NetworkPolicyMetricsList), b.(*metrics.NetworkPolicyMetricsList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*metrics.NetworkPolicyMetricsList)(nil), (*NetworkPolicyMetricsList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_metrics_NetworkPolicyMetricsList_To_v1alpha1_NetworkPolicyMetricsList(a.(*metrics.NetworkPolicyMetricsList), b.(*NetworkPolicyMetricsList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*TrafficStats)(nil), (*metrics.TrafficStats)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_TrafficStats_To_metrics_TrafficStats(a.(*TrafficStats), b.(*metrics.TrafficStats), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*metrics.TrafficStats)(nil), (*TrafficStats)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_metrics_TrafficStats_To_v1alpha1_TrafficStats(a.(*metrics.TrafficStats), b.(*TrafficStats), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_AntreaClusterNetworkPolicyMetrics_To_metrics_AntreaClusterNetworkPolicyMetrics(in *AntreaClusterNetworkPolicyMetrics, out *metrics.AntreaClusterNetworkPolicyMetrics, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_TrafficStats_To_metrics_TrafficStats(&in.TrafficStats, &out.TrafficStats, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_AntreaClusterNetworkPolicyMetrics_To_metrics_AntreaClusterNetworkPolicyMetrics is an autogenerated conversion function.
func Convert_v1alpha1_AntreaClusterNetworkPolicyMetrics_To_metrics_AntreaClusterNetworkPolicyMetrics(in *AntreaClusterNetworkPolicyMetrics, out *metrics.AntreaClusterNetworkPolicyMetrics, s conversion.Scope) error {
	return autoConvert_v1alpha1_AntreaClusterNetworkPolicyMetrics_To_metrics_AntreaClusterNetworkPolicyMetrics(in, out, s)
}

func autoConvert_metrics_AntreaClusterNetworkPolicyMetrics_To_v1alpha1_AntreaClusterNetworkPolicyMetrics(in *metrics.AntreaClusterNetworkPolicyMetrics, out *AntreaClusterNetworkPolicyMetrics, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_metrics_TrafficStats_To_v1alpha1_TrafficStats(&in.TrafficStats, &out.TrafficStats, s); err != nil {
		return err
	}
	return nil
}

// Convert_metrics_AntreaClusterNetworkPolicyMetrics_To_v1alpha1_AntreaClusterNetworkPolicyMetrics is an autogenerated conversion function.
func Convert_metrics_AntreaClusterNetworkPolicyMetrics_To_v1alpha1_AntreaClusterNetworkPolicyMetrics(in *metrics.AntreaClusterNetworkPolicyMetrics, out *AntreaClusterNetworkPolicyMetrics, s conversion.Scope) error {
	return autoConvert_metrics_AntreaClusterNetworkPolicyMetrics_To_v1alpha1_AntreaClusterNetworkPolicyMetrics(in, out, s)
}

func autoConvert_v1alpha1_AntreaClusterNetworkPolicyMetricsList_To_metrics_AntreaClusterNetworkPolicyMetricsList(in *AntreaClusterNetworkPolicyMetricsList, out *metrics.AntreaClusterNetworkPolicyMetricsList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]metrics.AntreaClusterNetworkPolicyMetrics)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_AntreaClusterNetworkPolicyMetricsList_To_metrics_AntreaClusterNetworkPolicyMetricsList is an autogenerated conversion function.
func Convert_v1alpha1_AntreaClusterNetworkPolicyMetricsList_To_metrics_AntreaClusterNetworkPolicyMetricsList(in *AntreaClusterNetworkPolicyMetricsList, out *metrics.AntreaClusterNetworkPolicyMetricsList, s conversion.Scope) error {
	return autoConvert_v1alpha1_AntreaClusterNetworkPolicyMetricsList_To_metrics_AntreaClusterNetworkPolicyMetricsList(in, out, s)
}

func autoConvert_metrics_AntreaClusterNetworkPolicyMetricsList_To_v1alpha1_AntreaClusterNetworkPolicyMetricsList(in *metrics.AntreaClusterNetworkPolicyMetricsList, out *AntreaClusterNetworkPolicyMetricsList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]AntreaClusterNetworkPolicyMetrics)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_metrics_AntreaClusterNetworkPolicyMetricsList_To_v1alpha1_AntreaClusterNetworkPolicyMetricsList is an autogenerated conversion function.
func Convert_metrics_AntreaClusterNetworkPolicyMetricsList_To_v1alpha1_AntreaClusterNetworkPolicyMetricsList(in *metrics.AntreaClusterNetworkPolicyMetricsList, out *AntreaClusterNetworkPolicyMetricsList, s conversion.Scope) error {
	return autoConvert_metrics_AntreaClusterNetworkPolicyMetricsList_To_v1alpha1_AntreaClusterNetworkPolicyMetricsList(in, out, s)
}

func autoConvert_v1alpha1_AntreaNetworkPolicyMetrics_To_metrics_AntreaNetworkPolicyMetrics(in *AntreaNetworkPolicyMetrics, out *metrics.AntreaNetworkPolicyMetrics, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_TrafficStats_To_metrics_TrafficStats(&in.TrafficStats, &out.TrafficStats, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_AntreaNetworkPolicyMetrics_To_metrics_AntreaNetworkPolicyMetrics is an autogenerated conversion function.
func Convert_v1alpha1_AntreaNetworkPolicyMetrics_To_metrics_AntreaNetworkPolicyMetrics(in *AntreaNetworkPolicyMetrics, out *metrics.AntreaNetworkPolicyMetrics, s conversion.Scope) error {
	return autoConvert_v1alpha1_AntreaNetworkPolicyMetrics_To_metrics_AntreaNetworkPolicyMetrics(in, out, s)
}

func autoConvert_metrics_AntreaNetworkPolicyMetrics_To_v1alpha1_AntreaNetworkPolicyMetrics(in *metrics.AntreaNetworkPolicyMetrics, out *AntreaNetworkPolicyMetrics, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_metrics_TrafficStats_To_v1alpha1_TrafficStats(&in.TrafficStats, &out.TrafficStats, s); err != nil {
		return err
	}
	return nil
}

// Convert_metrics_AntreaNetworkPolicyMetrics_To_v1alpha1_AntreaNetworkPolicyMetrics is an autogenerated conversion function.
func Convert_metrics_AntreaNetworkPolicyMetrics_To_v1alpha1_AntreaNetworkPolicyMetrics(in *metrics.AntreaNetworkPolicyMetrics, out *AntreaNetworkPolicyMetrics, s conversion.Scope) error {
	return autoConvert_metrics_AntreaNetworkPolicyMetrics_To_v1alpha1_AntreaNetworkPolicyMetrics(in, out, s)
}

func autoConvert_v1alpha1_AntreaNetworkPolicyMetricsList_To_metrics_AntreaNetworkPolicyMetricsList(in *AntreaNetworkPolicyMetricsList, out *metrics.AntreaNetworkPolicyMetricsList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]metrics.AntreaNetworkPolicyMetrics)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_AntreaNetworkPolicyMetricsList_To_metrics_AntreaNetworkPolicyMetricsList is an autogenerated conversion function.
func Convert_v1alpha1_AntreaNetworkPolicyMetricsList_To_metrics_AntreaNetworkPolicyMetricsList(in *AntreaNetworkPolicyMetricsList, out *metrics.AntreaNetworkPolicyMetricsList, s conversion.Scope) error {
	return autoConvert_v1alpha1_AntreaNetworkPolicyMetricsList_To_metrics_AntreaNetworkPolicyMetricsList(in, out, s)
}

func autoConvert_metrics_AntreaNetworkPolicyMetricsList_To_v1alpha1_AntreaNetworkPolicyMetricsList(in *metrics.AntreaNetworkPolicyMetricsList, out *AntreaNetworkPolicyMetricsList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]AntreaNetworkPolicyMetrics)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_metrics_AntreaNetworkPolicyMetricsList_To_v1alpha1_AntreaNetworkPolicyMetricsList is an autogenerated conversion function.
func Convert_metrics_AntreaNetworkPolicyMetricsList_To_v1alpha1_AntreaNetworkPolicyMetricsList(in *metrics.AntreaNetworkPolicyMetricsList, out *AntreaNetworkPolicyMetricsList, s conversion.Scope) error {
	return autoConvert_metrics_AntreaNetworkPolicyMetricsList_To_v1alpha1_AntreaNetworkPolicyMetricsList(in, out, s)
}

func autoConvert_v1alpha1_NetworkPolicyMetrics_To_metrics_NetworkPolicyMetrics(in *NetworkPolicyMetrics, out *metrics.NetworkPolicyMetrics, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_TrafficStats_To_metrics_TrafficStats(&in.TrafficStats, &out.TrafficStats, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_NetworkPolicyMetrics_To_metrics_NetworkPolicyMetrics is an autogenerated conversion function.
func Convert_v1alpha1_NetworkPolicyMetrics_To_metrics_NetworkPolicyMetrics(in *NetworkPolicyMetrics, out *metrics.NetworkPolicyMetrics, s conversion.Scope) error {
	return autoConvert_v1alpha1_NetworkPolicyMetrics_To_metrics_NetworkPolicyMetrics(in, out, s)
}

func autoConvert_metrics_NetworkPolicyMetrics_To_v1alpha1_NetworkPolicyMetrics(in *metrics.NetworkPolicyMetrics, out *NetworkPolicyMetrics, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_metrics_TrafficStats_To_v1alpha1_TrafficStats(&in.TrafficStats, &out.TrafficStats, s); err != nil {
		return err
	}
	return nil
}

// Convert_metrics_NetworkPolicyMetrics_To_v1alpha1_NetworkPolicyMetrics is an autogenerated conversion function.
func Convert_metrics_NetworkPolicyMetrics_To_v1alpha1_NetworkPolicyMetrics(in *metrics.NetworkPolicyMetrics, out *NetworkPolicyMetrics, s conversion.Scope) error {
	return autoConvert_metrics_NetworkPolicyMetrics_To_v1alpha1_NetworkPolicyMetrics(in, out, s)
}

func autoConvert_v1alpha1_NetworkPolicyMetricsList_To_metrics_NetworkPolicyMetricsList(in *NetworkPolicyMetricsList, out *metrics.NetworkPolicyMetricsList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]metrics.NetworkPolicyMetrics)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_NetworkPolicyMetricsList_To_metrics_NetworkPolicyMetricsList is an autogenerated conversion function.
func Convert_v1alpha1_NetworkPolicyMetricsList_To_metrics_NetworkPolicyMetricsList(in *NetworkPolicyMetricsList, out *metrics.NetworkPolicyMetricsList, s conversion.Scope) error {
	return autoConvert_v1alpha1_NetworkPolicyMetricsList_To_metrics_NetworkPolicyMetricsList(in, out, s)
}

func autoConvert_metrics_NetworkPolicyMetricsList_To_v1alpha1_NetworkPolicyMetricsList(in *metrics.NetworkPolicyMetricsList, out *NetworkPolicyMetricsList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]NetworkPolicyMetrics)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_metrics_NetworkPolicyMetricsList_To_v1alpha1_NetworkPolicyMetricsList is an autogenerated conversion function.
func Convert_metrics_NetworkPolicyMetricsList_To_v1alpha1_NetworkPolicyMetricsList(in *metrics.NetworkPolicyMetricsList, out *NetworkPolicyMetricsList, s conversion.Scope) error {
	return autoConvert_metrics_NetworkPolicyMetricsList_To_v1alpha1_NetworkPolicyMetricsList(in, out, s)
}

func autoConvert_v1alpha1_TrafficStats_To_metrics_TrafficStats(in *TrafficStats, out *metrics.TrafficStats, s conversion.Scope) error {
	out.Packets = in.Packets
	out.Bytes = in.Bytes
	out.Sessions = in.Sessions
	return nil
}

// Convert_v1alpha1_TrafficStats_To_metrics_TrafficStats is an autogenerated conversion function.
func Convert_v1alpha1_TrafficStats_To_metrics_TrafficStats(in *TrafficStats, out *metrics.TrafficStats, s conversion.Scope) error {
	return autoConvert_v1alpha1_TrafficStats_To_metrics_TrafficStats(in, out, s)
}

func autoConvert_metrics_TrafficStats_To_v1alpha1_TrafficStats(in *metrics.TrafficStats, out *TrafficStats, s conversion.Scope) error {
	out.Packets = in.Packets
	out.Bytes = in.Bytes
	out.Sessions = in.Sessions
	return nil
}

// Convert_metrics_TrafficStats_To_v1alpha1_TrafficStats is an autogenerated conversion function.
func Convert_metrics_TrafficStats_To_v1alpha1_TrafficStats(in *metrics.TrafficStats, out *TrafficStats, s conversion.Scope) error {
	return autoConvert_metrics_TrafficStats_To_v1alpha1_TrafficStats(in, out, s)
}
