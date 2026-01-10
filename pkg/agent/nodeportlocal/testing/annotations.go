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

package testing

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/nodeportlocal/types"
)

type ExpectedNPLAnnotations struct {
	nplStartPort int
	nplEndPort   int
	annotations  []types.NPLAnnotation
}

func NewExpectedNPLAnnotations(nplStartPort, nplEndPort int) *ExpectedNPLAnnotations {
	return &ExpectedNPLAnnotations{
		nplStartPort: nplStartPort,
		nplEndPort:   nplEndPort,
	}
}

func (a *ExpectedNPLAnnotations) find(podPort int, protocol string, ipFamily types.IPFamilyType) *types.NPLAnnotation {
	for idx := range a.annotations {
		annotation := &a.annotations[idx]
		if annotation.PodPort == podPort && annotation.Protocol == protocol && annotation.IPFamily == ipFamily {
			return annotation
		}
	}
	return nil
}

func (a *ExpectedNPLAnnotations) Add(ipFamily types.IPFamilyType, nodeIP *string, nodePort *int, podPort int, protocol string) *ExpectedNPLAnnotations {
	annotation := types.NPLAnnotation{PodPort: podPort, Protocol: protocol, IPFamily: ipFamily}
	if nodePort != nil {
		annotation.NodePort = *nodePort
	}
	if nodeIP != nil {
		annotation.NodeIP = *nodeIP
	}
	a.annotations = append(a.annotations, annotation)
	return a
}

func (a *ExpectedNPLAnnotations) Check(t *testing.T, nplValue []types.NPLAnnotation) {
	assert.Equal(t, len(a.annotations), len(nplValue), "Invalid number of NPL annotations")
	for _, nplAnnotation := range nplValue {
		expectedAnnotation := a.find(nplAnnotation.PodPort, nplAnnotation.Protocol, nplAnnotation.IPFamily)
		if !assert.NotNilf(t, expectedAnnotation, "Unexpected annotation with PodPort %d, Protocol %s, IPFamily %s", nplAnnotation.PodPort, nplAnnotation.Protocol, nplAnnotation.IPFamily) {
			continue
		}
		if expectedAnnotation.NodeIP != "" {
			assert.Equal(t, expectedAnnotation.NodeIP, nplAnnotation.NodeIP, "NodeIP mismatch in annotation")
		}
		if expectedAnnotation.NodePort != 0 {
			assert.Equal(t, expectedAnnotation.NodePort, nplAnnotation.NodePort, "NodePort mismatch in annotation")
		} else {
			assert.GreaterOrEqual(t, nplAnnotation.NodePort, a.nplStartPort)
			assert.LessOrEqual(t, nplAnnotation.NodePort, a.nplEndPort)
		}
	}
}

// Count returns the number of expected annotations, which corresponds to the number of Add calls
// made so far.
func (a *ExpectedNPLAnnotations) Count() int {
	return len(a.annotations)
}
