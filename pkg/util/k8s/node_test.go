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

package k8s

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetNodeAddr(t *testing.T) {
	tests := []struct {
		name         string
		node         *corev1.Node
		expectedAddr net.IP
		expectedErr  error
	}{
		{
			name: "internal address first",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.10.10",
						},
						{
							Type:    corev1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    corev1.NodeHostName,
							Address: "foo",
						},
					},
				},
			},
			expectedAddr: net.ParseIP("192.168.10.10"),
			expectedErr:  nil,
		},
		{
			name: "external address",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    corev1.NodeHostName,
							Address: "foo",
						},
					},
				},
			},
			expectedAddr: net.ParseIP("1.1.1.1"),
			expectedErr:  nil,
		},
		{
			name: "no valid address",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeHostName,
							Address: "foo",
						},
					},
				},
			},
			expectedAddr: nil,
			expectedErr:  fmt.Errorf("Node foo has neither external ip nor internal ip"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := GetNodeAddr(tt.node)
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedAddr, addr)
		})
	}
}
