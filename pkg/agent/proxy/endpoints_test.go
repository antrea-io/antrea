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

package proxy

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
)

func BenchmarkEndpointsChangesTrackerOnEndpointUpdate(b *testing.B) {
	var oldAddresses []corev1.EndpointAddress
	nodeName := rand.String(20)
	resourceVersion := fmt.Sprintf("%d", rand.Int())
	for i := 0; i < 10; i++ {
		oldAddresses = append(oldAddresses, corev1.EndpointAddress{
			IP:       fmt.Sprintf("1.1.1.%d", i),
			NodeName: &nodeName,
			TargetRef: &corev1.ObjectReference{
				Kind:            "Pod",
				Namespace:       "default",
				Name:            rand.String(10),
				UID:             types.UID(uuid.New().String()),
				ResourceVersion: resourceVersion,
			},
		})
	}
	oldEndpoints := makeTestEndpoints("foo", "bar", func(ept *corev1.Endpoints) {
		ept.Subsets = []corev1.EndpointSubset{{
			Addresses: oldAddresses,
			Ports: []corev1.EndpointPort{{
				Name:     "http",
				Port:     int32(80),
				Protocol: corev1.ProtocolTCP,
			}},
		}}
	})

	for _, tc := range []struct {
		name       string
		mutateFunc func(endpoints *corev1.Endpoints)
	}{
		{
			name:       "equal",
			mutateFunc: nil,
		},
		{
			name: "not equal, same length",
			mutateFunc: func(endpoints *corev1.Endpoints) {
				endpoints.Subsets[0].Addresses[5].IP = "2.2.2.2"
			},
		},
		{
			name: "not equal, different length",
			mutateFunc: func(endpoints *corev1.Endpoints) {
				numAddresses := len(endpoints.Subsets[0].Addresses)
				endpoints.Subsets[0].Addresses = endpoints.Subsets[0].Addresses[0 : numAddresses-1]
			},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			newEndpoints := oldEndpoints.DeepCopy()
			if tc.mutateFunc != nil {
				tc.mutateFunc(newEndpoints)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t := newEndpointsChangesTracker("node1", false, false)
				t.OnEndpointUpdate(oldEndpoints, newEndpoints)
			}
		})
	}

}
