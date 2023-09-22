/*
Copyright 2021 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commonarea

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/test/mocks"
)

func TestMemberAnnounce(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockManager := mocks.NewMockManager(mockCtrl)
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()

	remoteCommonAreaUnderTest := &remoteCommonArea{
		Client:             fakeRemoteClient,
		ClusterManager:     mockManager, // Ok to use a mock as long the remoteCommonArea.StartWatching is not tested
		ClusterSetID:       "clusterSetA",
		ClusterID:          "leaderA",
		localClusterID:     "clusterA",
		config:             nil, // Not used for this test
		scheme:             common.TestScheme,
		Namespace:          "cluster-a-ns",
		connected:          false,
		localClusterClient: nil, // Not used for this test
	}

	remoteCommonAreaUnderTest.Start()

	done := make(chan bool)

	go func() {
		// Test that member announce is written to the fakeRemoteClient
		ctx := context.Background()
		memberAnnounceList := &mcv1alpha1.MemberClusterAnnounceList{}

		for i := 0; i < 10; i++ {
			time.Sleep(1 * time.Second)

			err := fakeRemoteClient.List(ctx, memberAnnounceList, client.InNamespace("cluster-a-ns"))
			if err != nil {
				klog.InfoS("member announce not written to remote cluster %v yet", err)
				continue
			}

			if !remoteCommonAreaUnderTest.IsConnected() {
				klog.InfoS("Remote cluster not marked as connected yet")
				continue
			}
			done <- true
		}
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		panic("timeout")
	}

	remoteCommonAreaUnderTest.Stop()
}

func TestMemberAnnounceWithExistingMemberAnnounce(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockManager := mocks.NewMockManager(mockCtrl)
	existingMemberClusterAnnounce := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "cluster-a-ns",
			Name:       "member-announce-from-clusterA",
			Generation: 1,
		},
	}
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingMemberClusterAnnounce).Build()

	remoteCommonAreaUnderTest := &remoteCommonArea{
		Client:             fakeRemoteClient,
		ClusterManager:     mockManager, // Ok to use a mock as long the remoteCommonArea.StartWatching is not tested
		ClusterSetID:       "clusterSetA",
		ClusterID:          "leaderA",
		localClusterID:     "clusterA",
		config:             nil, // Not used for this test
		scheme:             common.TestScheme,
		Namespace:          "cluster-a-ns",
		connected:          false,
		localClusterClient: nil, // Not used for this test
		leaderStatus: mcv1alpha2.ClusterCondition{
			Message: "Leader cluster added",
			Status:  v1.ConditionFalse,
			Type:    mcv1alpha2.ClusterIsLeader,
		},
	}

	remoteCommonAreaUnderTest.Start()

	done := make(chan bool)

	go func() {
		// Test that member announce is written to the fakeRemoteClient
		ctx := context.Background()
		memberAnnounceList := &mcv1alpha1.MemberClusterAnnounceList{}

		for i := 0; i < 10; i++ {
			time.Sleep(1 * time.Second)

			err := fakeRemoteClient.List(ctx, memberAnnounceList, client.InNamespace("cluster-a-ns"))
			if err != nil {
				klog.InfoS("member announce not written to remote cluster %v yet", err)
				continue
			}

			if !remoteCommonAreaUnderTest.IsConnected() {
				klog.InfoS("Remote cluster not marked as connected yet")
				continue
			}
			done <- true
		}
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		panic("timeout")
	}

	defer remoteCommonAreaUnderTest.Stop()
	status := remoteCommonAreaUnderTest.GetStatus()

	assert.Equal(t, v1.ConditionTrue, status[0].Status)
	assert.Equal(t, v1.ConditionTrue, status[1].Status)
	assert.Equal(t, "", status[0].Reason)
	assert.Equal(t, "", status[1].Reason)
	assert.Equal(t, "", status[0].Message)
	assert.Equal(t, "This leader cluster is the leader for local cluster", status[1].Message)
	assert.Equal(t, mcv1alpha2.ClusterConditionType(""), status[0].Type)
	assert.Equal(t, mcv1alpha2.ClusterIsLeader, status[1].Type)
}

func TestMemberAnnounceNewRemoteCommonArea(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockManager := mocks.NewMockManager(mockCtrl)
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()

	expectedRemoteCommonArea := &remoteCommonArea{
		Client:             fakeRemoteClient,
		ClusterManager:     mockManager,
		ClusterSetID:       "clusterSetA",
		ClusterID:          "leaderA",
		config:             nil,
		scheme:             common.TestScheme,
		Namespace:          "cluster-a-ns",
		connected:          false,
		localClusterClient: nil,
		localNamespace:     "localnamespace",
		localClusterID:     "clusterA",
		clusterStatus: mcv1alpha2.ClusterCondition{
			Type:    mcv1alpha2.ClusterReady,
			Status:  v1.ConditionUnknown,
			Message: "Leader cluster added",
		},
		leaderStatus: mcv1alpha2.ClusterCondition{
			Type:    mcv1alpha2.ClusterIsLeader,
			Status:  v1.ConditionFalse,
			Message: "Leader cluster added",
		},
	}

	actualRemoteCommonArea, err := NewRemoteCommonArea(expectedRemoteCommonArea.ClusterID, expectedRemoteCommonArea.ClusterSetID, expectedRemoteCommonArea.localClusterID, mockManager, fakeRemoteClient, common.TestScheme, nil,
		"cluster-a-ns", "localnamespace", nil, false)
	assert.Equal(t, nil, err)
	clusterStatus, leaderStatus := actualRemoteCommonArea.GetStatus()[0], actualRemoteCommonArea.GetStatus()[1]
	// Assign LastTransitionTime to clusterStatus and leaderStatus of expectedRemoteCommonArea to simply the following comparison.
	expectedRemoteCommonArea.clusterStatus.LastTransitionTime = clusterStatus.LastTransitionTime
	expectedRemoteCommonArea.leaderStatus.LastTransitionTime = leaderStatus.LastTransitionTime
	assert.Equal(t, expectedRemoteCommonArea, actualRemoteCommonArea)
}

func TestMemberAnnounceGetSecretCACrtAndToken(t *testing.T) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "member-token",
		},
		Data: map[string][]byte{
			"ca.crt": []byte(`12345`),
			"token":  []byte(`12345`)},
	}
	secretNoRootCAKey := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "member-token",
		},
		Data: map[string][]byte{
			"token": []byte(`12345`)},
	}
	secretNoTokenKey := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "member-token",
		},
		Data: map[string][]byte{
			"ca.crt": []byte(`12345`),
		},
	}

	tests := []struct {
		name          string
		secret        *v1.Secret
		caData        []byte
		token         []byte
		expectedError error
	}{
		{
			name:   "with  ca.crt data and token",
			secret: secret,
			caData: []byte(`12345`),
			token:  []byte(`12345`),
		},
		{
			name:          "with no ca.crt data",
			secret:        secretNoRootCAKey,
			caData:        nil,
			token:         nil,
			expectedError: fmt.Errorf("ca.crt data not found in Secret member-token"),
		},
		{
			name:          "with no token",
			secret:        secretNoTokenKey,
			caData:        nil,
			token:         nil,
			expectedError: fmt.Errorf("token not found in Secret member-token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caData, token, err := getSecretCACrtAndToken(tt.secret)
			assert.Equal(t, tt.caData, caData)
			assert.Equal(t, tt.token, token)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}
