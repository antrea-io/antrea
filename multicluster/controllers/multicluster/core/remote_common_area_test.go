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

package core

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/test/mocks"
)

var (
	fakeRemoteClient = fake.NewClientBuilder().WithScheme(scheme).Build()
)

func TestMemberAnnounce(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockRemoteCommonAreaManager := NewMockRemoteCommonAreaManager(mockCtrl)
	mockRemoteCommonAreaManager.EXPECT().GetLocalClusterID().Return(common.ClusterID("memberA")).AnyTimes()
	mockManager := mocks.NewMockManager(mockCtrl)

	remoteCommonAreaUnderTest := &remoteCommonArea{
		Client:                  fakeRemoteClient,
		ClusterManager:          mockManager, // Ok to use a mock as long the remoteCommonArea.StartWatching is not tested
		ClusterSetID:            "clusterSetA",
		ClusterID:               "leaderA",
		config:                  nil, // Not used for this test
		scheme:                  scheme,
		Namespace:               "cluster-a-ns",
		connected:               false,
		localClusterClient:      nil, // Not used for this test
		remoteCommonAreaManager: mockRemoteCommonAreaManager,
	}

	remoteCommonAreaUnderTest.Start()

	done := make(chan bool)

	go func() {
		// Test that member announce is written to the fakeRemoteClient
		ctx := context.Background()
		memberAnnounceList := &mcsv1alpha1.MemberClusterAnnounceList{}

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
	case <-time.After(10 * time.Second):
		panic("timeout")
	}

	remoteCommonAreaUnderTest.Stop()
}
