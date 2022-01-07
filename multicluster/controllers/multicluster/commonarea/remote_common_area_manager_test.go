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
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	k8smcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	rcmtScheme = runtime.NewScheme()
)

func TestAddMember(t *testing.T) {

	remoteCommonAreaManagerUnderTest := NewRemoteCommonAreaManager(common.ClusterSetID("clusterSetA"), common.ClusterID("memberA"))

	remoteCommonAreaManagerUnderTest.Start()
	mockCtrl := gomock.NewController(t)
	mockRemoteCommonArea := NewMockRemoteCommonArea(mockCtrl)

	mockRemoteCommonArea.EXPECT().GetClusterID().Return(common.ClusterID("leaderA")).AnyTimes()
	mockRemoteCommonArea.EXPECT().IsConnected().Return(true).AnyTimes()
	mockRemoteCommonArea.EXPECT().Start()
	mockRemoteCommonArea.EXPECT().StartWatching()

	remoteCommonAreaManagerUnderTest.AddRemoteCommonArea(mockRemoteCommonArea)

	done := make(chan bool)

	go func() {

		for i := 0; i <= 10; i++ {
			time.Sleep(2 * time.Second)

			if remoteCommonAreaManagerUnderTest.GetElectedLeaderClusterID() != "leaderA" {
				klog.InfoS("Leader election not complete yet")
				continue
			}
			klog.InfoS("Leader election completed")

			done <- true
		}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		panic("timeout")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	mockRemoteCommonArea.EXPECT().Stop().Do(func() {
		wg.Done()
	})

	remoteCommonAreaManagerUnderTest.Stop()
}

func TestLeaderElection(t *testing.T) {

	remoteCommonAreaManagerUnderTest := NewRemoteCommonAreaManager("clusterSetA", "memberA")
	remoteCommonAreaManagerUnderTest.Start()

	mockCtrl := gomock.NewController(t)
	mockRemoteCommonArea1 := NewMockRemoteCommonArea(mockCtrl)
	mockRemoteCommonArea1.EXPECT().GetClusterID().Return(common.ClusterID("leaderA1")).AnyTimes()
	var i = 0
	mockRemoteCommonArea1.EXPECT().IsConnected().DoAndReturn(
		func() (connected bool) {
			defer func() { i += 1 }()
			return i < 2
		}).AnyTimes()
	mockRemoteCommonArea1.EXPECT().Start()
	mockRemoteCommonArea1.EXPECT().StartWatching()
	mockRemoteCommonArea1.EXPECT().StopWatching()

	mockRemoteCommonArea2 := NewMockRemoteCommonArea(mockCtrl)
	mockRemoteCommonArea2.EXPECT().GetClusterID().Return(common.ClusterID("leaderA2")).AnyTimes()
	var j = 0
	mockRemoteCommonArea2.EXPECT().IsConnected().DoAndReturn(
		func() (connected bool) {
			defer func() { j += 1 }()
			return j >= 2
		}).AnyTimes()
	mockRemoteCommonArea2.EXPECT().Start()
	mockRemoteCommonArea2.EXPECT().StartWatching()

	remoteCommonAreaManagerUnderTest.AddRemoteCommonArea(mockRemoteCommonArea1)
	remoteCommonAreaManagerUnderTest.AddRemoteCommonArea(mockRemoteCommonArea2)

	done := make(chan bool)

	go func() {

		firstElectionDone := false
		for i := 0; i <= 13; i++ {
			time.Sleep(2 * time.Second)
			if !firstElectionDone {
				leader := remoteCommonAreaManagerUnderTest.GetElectedLeaderClusterID()
				if leader != "leaderA1" {
					klog.InfoS("Leader election not complete yet")
					continue
				}
				klog.InfoS("Leader election completed")
				firstElectionDone = true
			}

			if remoteCommonAreaManagerUnderTest.GetElectedLeaderClusterID() != "leaderA2" {
				klog.InfoS("Leader has not changed yet")
				continue
			}

			done <- true
		}
	}()

	select {
	case <-done:
	case <-time.After(25 * time.Second):
		panic("timeout")
	}

	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()
	mockRemoteCommonArea1.EXPECT().Stop().Do(func() {
		wg.Done()
	})
	mockRemoteCommonArea2.EXPECT().Stop().Do(func() {
		wg.Done()
	})

	remoteCommonAreaManagerUnderTest.Stop()
}

func init() {
	utilruntime.Must(mcsv1alpha1.AddToScheme(rcmtScheme))
	utilruntime.Must(k8smcsapi.AddToScheme(rcmtScheme))
	utilruntime.Must(k8sscheme.AddToScheme(rcmtScheme))
}
