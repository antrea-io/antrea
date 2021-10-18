//go:build !windows
// +build !windows

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

	nplk8s "antrea.io/antrea/pkg/agent/nodeportlocal/k8s"
)

type ExpectedNPLAnnotations struct {
	nodeIP       *string
	nplStartPort int
	nplEndPort   int
	annotations  []nplk8s.NPLAnnotation
}

func NewExpectedNPLAnnotations(nodeIP *string, nplStartPort, nplEndPort int) *ExpectedNPLAnnotations {
	return &ExpectedNPLAnnotations{
		nodeIP:       nodeIP,
		nplStartPort: nplStartPort,
		nplEndPort:   nplEndPort,
	}
}

func (a *ExpectedNPLAnnotations) find(podPort int) *nplk8s.NPLAnnotation {
	for _, annotation := range a.annotations {
		if annotation.PodPort == podPort {
			return &annotation
		}
	}
	return nil
}

func (a *ExpectedNPLAnnotations) Add(nodePort *int, podPort int, protocols ...string) *ExpectedNPLAnnotations {
	for i, annotation := range a.annotations {
		if annotation.PodPort == podPort {
			annotation.Protocols = append(annotation.Protocols, protocols...)
			a.annotations[i] = annotation
			return a
		}
	}
	annotation := nplk8s.NPLAnnotation{PodPort: podPort, Protocols: protocols}
	if nodePort != nil {
		annotation.NodePort = *nodePort
	}
	if a.nodeIP != nil {
		annotation.NodeIP = *a.nodeIP
	}
	a.annotations = append(a.annotations, annotation)
	return a
}

func (a *ExpectedNPLAnnotations) Check(t *testing.T, nplValue []nplk8s.NPLAnnotation) {
	assert.Equal(t, len(a.annotations), len(nplValue), "Invalid number of NPL annotations")
	nodePorts := make(map[int]bool)
	for _, nplAnnotation := range nplValue {
		assert.NotContains(t, nodePorts, nplAnnotation.NodePort, "Duplicate Node ports in NPL annotations")
		nodePorts[nplAnnotation.NodePort] = true
		expectedAnnotation := a.find(nplAnnotation.PodPort)
		if !assert.NotNilf(t, expectedAnnotation, "Unexpected annotation with PodPort %d", nplAnnotation.PodPort) {
			continue
		}
		assert.ElementsMatch(t, expectedAnnotation.Protocols, nplAnnotation.Protocols, "Protocols mismatch in annotation")
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
