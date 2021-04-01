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
	crdv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
)

func Test_getNetworkPolicyObservation(t *testing.T) {
	type args struct {
		tableID uint8
		ingress bool
	}
	tests := []struct {
		name string
		args args
		want *crdv1alpha1.Observation
	}{
		{
			name: "ingress metric drop",
			args: args{
				tableID: uint8(openflow.IngressMetricTable),
				ingress: true,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "IngressMetric",
				Action:        crdv1alpha1.ActionDropped,
			},
		},
		{
			name: "ingress accept",
			args: args{
				tableID: uint8(openflow.L2ForwardingOutTable),
				ingress: true,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "IngressRule",
				Action:        crdv1alpha1.ActionForwarded,
			},
		},
		{
			name: "egress default drop",
			args: args{
				tableID: uint8(openflow.EgressDefaultTable),
				ingress: false,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "EgressDefaultRule",
				Action:        crdv1alpha1.ActionDropped,
			},
		},
		{
			name: "egress accept",
			args: args{
				tableID: uint8(openflow.L2ForwardingOutTable),
				ingress: false,
			},
			want: &crdv1alpha1.Observation{
				Component:     crdv1alpha1.ComponentNetworkPolicy,
				ComponentInfo: "EgressRule",
				Action:        crdv1alpha1.ActionForwarded,
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
