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

package traceflow

import (
	"reflect"
	"testing"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
)

func Test_getNetworkPolicyObservation(t *testing.T) {
	type args struct {
		tableID uint8
		ingress bool
	}
	tests := []struct {
		name string
		args args
		want *opsv1alpha1.Observation
	}{
		{
			name: "ingress metric drop",
			args: args{
				tableID: uint8(openflow.IngressMetricTable),
				ingress: true,
			},
			want: &opsv1alpha1.Observation{
				Component:     opsv1alpha1.NetworkPolicy,
				ComponentInfo: "IngressMetric",
				Action:        opsv1alpha1.Dropped,
			},
		},
		{
			name: "ingress accept",
			args: args{
				tableID: uint8(openflow.L2ForwardingOutTable),
				ingress: true,
			},
			want: &opsv1alpha1.Observation{
				Component:     opsv1alpha1.NetworkPolicy,
				ComponentInfo: "IngressRule",
				Action:        opsv1alpha1.Forwarded,
			},
		},
		{
			name: "egress default drop",
			args: args{
				tableID: uint8(openflow.EgressDefaultTable),
				ingress: false,
			},
			want: &opsv1alpha1.Observation{
				Component:     opsv1alpha1.NetworkPolicy,
				ComponentInfo: "EgressDefaultRule",
				Action:        opsv1alpha1.Dropped,
			},
		},
		{
			name: "egress accept",
			args: args{
				tableID: uint8(openflow.L2ForwardingOutTable),
				ingress: false,
			},
			want: &opsv1alpha1.Observation{
				Component:     opsv1alpha1.NetworkPolicy,
				ComponentInfo: "EgressRule",
				Action:        opsv1alpha1.Forwarded,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getNetworkPolicyObservation(tt.args.tableID, tt.args.ingress); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getNetworkPolicyObservation() = %v, want %v", got, tt.want)
			}
		})
	}
}
