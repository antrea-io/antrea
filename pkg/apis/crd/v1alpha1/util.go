// Copyright 2025 Antrea Authors
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

package v1alpha1

import (
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
)

// ConditionEqualsIgnoreLastTransitionTime checks equality of two conditions, ignoring the
// LastTransitionTime field. It must be exported because it is used directly by the
// packetcapture controller's mergeConditions logic.
func ConditionEqualsIgnoreLastTransitionTime(a, b PacketCaptureCondition) bool {
	a1 := a
	a1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	b1 := b
	b1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return a1 == b1
}

func ConditionSliceEqualsIgnoreLastTransitionTime(as, bs []PacketCaptureCondition) bool {
	sort.Slice(as, func(i, j int) bool {
		return as[i].Type < as[j].Type
	})
	sort.Slice(bs, func(i, j int) bool {
		return bs[i].Type < bs[j].Type
	})

	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		a := as[i]
		b := bs[i]
		if !ConditionEqualsIgnoreLastTransitionTime(a, b) {
			return false
		}
	}
	return true
}

var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	ConditionSliceEqualsIgnoreLastTransitionTime,
)

// PacketCaptureStatusEqual performs a semantic deep equality check between two
// PacketCaptureStatus objects.
func PacketCaptureStatusEqual(oldStatus, newStatus PacketCaptureStatus) bool {
	return semanticIgnoreLastTransitionTime.DeepEqual(oldStatus, newStatus)
}

func (proto *FlowExporterGRPCConfig) Name() string {
	return "grpc"
}

func (proto *FlowExporterIPFIXConfig) Name() string {
	return "ipfix"
}

func (proto *FlowExporterGRPCConfig) TransportProtocol() FlowExporterTransportProtocol {
	return FlowExporterTransportTLS
}

func (proto *FlowExporterIPFIXConfig) TransportProtocol() FlowExporterTransportProtocol {
	return proto.Transport
}
