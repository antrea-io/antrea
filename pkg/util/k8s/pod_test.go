// Copyright 2025 Antrea Authors.
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
	"context"
	"errors"
	"testing"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestUpdatePodNetworkStatusAnnotation(t *testing.T) {
	ctx := context.Background()
	podName := "test-pod"
	podNamespace := "default"
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: podNamespace,
		},
	}
	testCases := []struct {
		name                   string
		podAnnot               map[string]string
		netStatus              []netdefv1.NetworkStatus
		isPrimary              bool
		getPodErr              error
		getNetworkStatusCalled bool
		getStatusErr           error
		setNetworkStatusCalled bool
		setStatusErr           error
		expectErrStr           string
		expectStatus           []netdefv1.NetworkStatus
	}{
		{
			name:         "empty status skips update",
			netStatus:    nil,
			expectErrStr: "context deadline exceeded",
		},
		{
			name:         "get pod failure",
			netStatus:    []netdefv1.NetworkStatus{{Name: "eth1"}},
			getPodErr:    errors.New("api down"),
			expectErrStr: "api down",
		},
		{
			name:                   "get status failure",
			netStatus:              []netdefv1.NetworkStatus{{Name: "eth1"}},
			getNetworkStatusCalled: true,
			getStatusErr:           errors.New("parse error"),
			expectStatus:           []netdefv1.NetworkStatus{{Name: "eth1"}},
		},
		{
			name: "set status failure",
			podAnnot: map[string]string{"k8s.v1.cni.cncf.io/network-status": `[{
    "name": "eth0",
    "ips": [
        "192.168.1.2"
    ],
    "dns": {}
}]`},
			netStatus:              []netdefv1.NetworkStatus{{Name: "eth1"}},
			setNetworkStatusCalled: true,
			setStatusErr:           errors.New("update conflict"),
		},
		{
			name:         "primary update with Pod nil annotation",
			netStatus:    []netdefv1.NetworkStatus{{Name: "eth0", IPs: []string{"192.168.1.2"}}},
			isPrimary:    true,
			expectErrStr: "skipping network status update for the Pod annotation is nil",
		},
		{
			name:         "primary update without Pod k8s.v1.cni.cncf.io/networks annotation",
			podAnnot:     map[string]string{"fake-anno": "fake-value"},
			netStatus:    []netdefv1.NetworkStatus{{Name: "eth0", IPs: []string{"192.168.1.2"}}},
			isPrimary:    true,
			expectErrStr: "skipping network status update as the Pod without annotation k8s.v1.cni.cncf.io/networks",
		},
		{
			name: "primary update replaces existing",
			podAnnot: map[string]string{
				netdefv1.NetworkAttachmentAnnot: `[{"name": "sriov-net1", "namespace": "default", "interface": "eth1"}]`,
				netdefv1.NetworkStatusAnnot: `[{
    "name": "eth0",
    "ips": [
        "192.168.1.2"
    ],
    "dns": {}
}]`,
			},
			netStatus:    []netdefv1.NetworkStatus{{Name: "eth0", IPs: []string{"192.168.1.2"}}},
			isPrimary:    true,
			expectStatus: []netdefv1.NetworkStatus{{Name: "eth0", IPs: []string{"192.168.1.2"}}},
		},
		{
			name: "secondary update appends",
			podAnnot: map[string]string{
				netdefv1.NetworkAttachmentAnnot: `[{"name": "sriov-net1", "namespace": "default", "interface": "eth1"}]`,
				netdefv1.NetworkStatusAnnot: `[{
    "name": "eth0",
    "ips": [
        "192.168.1.2"
    ],
    "dns": {}
}]`,
			},
			netStatus:    []netdefv1.NetworkStatus{{Name: "eth1"}},
			isPrimary:    false,
			expectStatus: []netdefv1.NetworkStatus{{Name: "eth0", IPs: []string{"192.168.1.2"}}, {Name: "eth1"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testPod.Annotations = tc.podAnnot
			client := fake.NewSimpleClientset(testPod.DeepCopy())

			var getNetworkStatusCalled bool
			var setNetworkStatusCalled bool
			defer mockNetdefutilsGetNetworkStatus(tc.getStatusErr, &getNetworkStatusCalled)()
			defer mockNetdefutilsSetNetworkStatus(tc.setStatusErr, &setNetworkStatusCalled)()

			if tc.getPodErr != nil {
				client.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, tc.getPodErr
				})
			}

			err := UpdatePodNetworkStatusAnnotation(client, ctx, tc.netStatus, "test-pod", "default", tc.isPrimary)
			if err != nil {
				assert.Contains(t, err.Error(), tc.expectErrStr)
			}
			assert.Equal(t, tc.getNetworkStatusCalled, getNetworkStatusCalled)
			assert.Equal(t, tc.setNetworkStatusCalled, setNetworkStatusCalled)
			if err == nil {
				podItem, err := client.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
				assert.NoError(t, err)
				networkStatus, _ := netdefutils.GetNetworkStatus(podItem)
				assert.ElementsMatch(t, tc.expectStatus, networkStatus)
			}
		})
	}
}

func mockNetdefutilsSetNetworkStatus(err error, called *bool) func() {
	origSetStatus := netdefutils.SetNetworkStatus
	if err != nil {
		netdefutilsSetNetworkStatus = func(client clientset.Interface, pod *corev1.Pod, status []netdefv1.NetworkStatus) error {
			*called = true
			return err
		}
	}
	return func() {
		netdefutilsSetNetworkStatus = origSetStatus
	}
}

func mockNetdefutilsGetNetworkStatus(err error, called *bool) func() {
	origGetStatus := netdefutils.GetNetworkStatus
	if err != nil {
		netdefutilsGetNetworkStatus = func(pod *corev1.Pod) ([]netdefv1.NetworkStatus, error) {
			*called = true
			return nil, err
		}
	}
	return func() {
		netdefutilsGetNetworkStatus = origGetStatus
	}
}
