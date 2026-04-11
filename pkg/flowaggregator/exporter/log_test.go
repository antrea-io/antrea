// Copyright 2023 Antrea Authors
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

package exporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
	"antrea.io/antrea/v2/pkg/flowaggregator/flowrecord"
	"antrea.io/antrea/v2/pkg/flowaggregator/options"
)

func TestLog_Filters(t *testing.T) {
	type testRecord struct {
		name string
		*flowrecord.FlowRecord
	}
	unprotectedRec := &testRecord{
		name:       "unprotected",
		FlowRecord: &flowrecord.FlowRecord{},
	}
	droppedByEgressRec := &testRecord{
		name: "dropped-by-egress",
		FlowRecord: &flowrecord.FlowRecord{
			EgressNetworkPolicyRuleAction: 2,
		},
	}
	rejectedByIngressRec := &testRecord{
		name: "rejected-by-ingress",
		FlowRecord: &flowrecord.FlowRecord{
			IngressNetworkPolicyRuleAction: 3,
		},
	}
	allowedByBothRec := &testRecord{
		name: "allowed-by-both-sides",
		FlowRecord: &flowrecord.FlowRecord{
			IngressNetworkPolicyRuleAction: 1,
			EgressNetworkPolicyRuleAction:  1,
		},
	}
	testCases := []struct {
		name        string
		filters     []flowaggregatorconfig.FlowFilter
		testRecords map[*testRecord]bool
	}{
		{
			name:    "no filter",
			filters: []flowaggregatorconfig.FlowFilter{},
			testRecords: map[*testRecord]bool{
				unprotectedRec:       true,
				droppedByEgressRec:   true,
				rejectedByIngressRec: true,
				allowedByBothRec:     true,
			},
		},
		{
			name: "ingress and egress unprotected",
			filters: []flowaggregatorconfig.FlowFilter{
				{
					IngressNetworkPolicyRuleActions: []flowaggregatorconfig.NetworkPolicyRuleAction{flowaggregatorconfig.NetworkPolicyRuleActionNone},
					EgressNetworkPolicyRuleActions:  []flowaggregatorconfig.NetworkPolicyRuleAction{flowaggregatorconfig.NetworkPolicyRuleActionNone},
				},
			},
			testRecords: map[*testRecord]bool{
				unprotectedRec:       true,
				droppedByEgressRec:   false,
				rejectedByIngressRec: false,
				allowedByBothRec:     false,
			},
		},
		{
			name: "denied only",
			filters: []flowaggregatorconfig.FlowFilter{
				{
					IngressNetworkPolicyRuleActions: []flowaggregatorconfig.NetworkPolicyRuleAction{flowaggregatorconfig.NetworkPolicyRuleActionDrop, flowaggregatorconfig.NetworkPolicyRuleActionReject},
				},
				{
					EgressNetworkPolicyRuleActions: []flowaggregatorconfig.NetworkPolicyRuleAction{flowaggregatorconfig.NetworkPolicyRuleActionDrop, flowaggregatorconfig.NetworkPolicyRuleActionReject},
				},
			},
			testRecords: map[*testRecord]bool{
				unprotectedRec:       false,
				droppedByEgressRec:   true,
				rejectedByIngressRec: true,
				allowedByBothRec:     false,
			},
		},
		{
			name: "ingress and / or egress unprotected",
			filters: []flowaggregatorconfig.FlowFilter{
				{
					IngressNetworkPolicyRuleActions: []flowaggregatorconfig.NetworkPolicyRuleAction{flowaggregatorconfig.NetworkPolicyRuleActionNone},
				},
				{
					EgressNetworkPolicyRuleActions: []flowaggregatorconfig.NetworkPolicyRuleAction{flowaggregatorconfig.NetworkPolicyRuleActionNone},
				},
			},
			testRecords: map[*testRecord]bool{
				unprotectedRec:       true,
				droppedByEgressRec:   true,
				rejectedByIngressRec: true,
				allowedByBothRec:     false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opt := &options.Options{
				Config: &flowaggregatorconfig.FlowAggregatorConfig{
					FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
						Enable:      true,
						Path:        "/tmp/antrea-flows.log",
						Compress:    new(bool),
						PrettyPrint: new(bool),
						Filters:     tc.filters,
					},
				},
			}
			logExporter, err := NewLogExporter(opt)
			require.NoError(t, err)
			for record, expected := range tc.testRecords {
				assert.Equal(t, expected, logExporter.applyFilters(record.FlowRecord), "unexpected result for record %s", record.name)
			}
		})
	}
}
