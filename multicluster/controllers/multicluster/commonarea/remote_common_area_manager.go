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
	"sync"
	"time"

	"k8s.io/klog/v2"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

type clusterEvent struct {
	isAdd            bool
	remoteCommonArea RemoteCommonArea
}

type RemoteCommonAreaManager interface {
	// Start starts RemoteCommonAreaManager on an event loop which runs in a goroutine
	Start() error
	// Stop stops RemoteCommonAreaManager by terminating the event loop.
	Stop() error
	// AddRemoteCommonArea adds a RemoteCommonArea to RemoteCommonAreaManager.
	AddRemoteCommonArea(remoteCommonArea RemoteCommonArea)
	// RemoveRemoteCommonArea removes a RemoteCommonArea from RemoteCommonAreaManager.
	RemoveRemoteCommonArea(remoteCluster RemoteCommonArea)
	// GetRemoteCommonAreas returns all RemoteCommonArea
	GetRemoteCommonAreas() map[common.ClusterID]RemoteCommonArea
	// GetElectedLeaderClusterID returns the elected, leader RemoteCommonArea or InvalidClusterID if none elected
	GetElectedLeaderClusterID() common.ClusterID
	// GetLocalClusterID returns local cluster ID
	GetLocalClusterID() common.ClusterID
	GetMemberClusterStatues() []multiclusterv1alpha1.ClusterStatus
}

// remoteCommonAreaManager implements the interface RemoteCommonAreaManager.
// It manages all leaders defined in the ClusterSet and manages CommonArea access into them.
// It also implements LeaderElector which finds an elected-leader from which resources
// must be monitored.
type remoteCommonAreaManager struct {
	// mutex for synchronizing access to fields that are concurrently accessed.
	mutex sync.Mutex

	clusterSetID common.ClusterSetID

	// remoteCommonAreas is a map of RemoteCommonArea.
	// It is accessed only from the event-loop in a single goroutine context.
	remoteCommonAreas map[common.ClusterID]RemoteCommonArea

	remoteCommonAreaStatus map[common.ClusterID]multiclusterv1alpha1.ClusterCondition

	// electedLeaderCluster is a RemoteCommonArea which is an elected-leader.
	// It is access from 2 contexts and protected by the mutex
	// 1. eventloop
	// 2. RemoteCommonArea background go routine
	electedLeaderCluster RemoteCommonArea

	// needElection tracks whether election is needed.
	// It is only accessed in LeaderElector context.
	needElection bool

	// clusterID is the local clusterID.
	// This is a constant.
	clusterID common.ClusterID

	// eventChan is a channel which will process clusterEvents like RemoteCommonArea add/remove.
	eventChan chan clusterEvent

	// clusterSyncMap is a copy of remoteCommonAreas for access from ClusterSet reconciler
	// to avoid locking on remoteCommonAreas from the reconciler context.
	clusterSyncMap sync.Map

	// stopFunc is to stop all background processing when RemoteCommonAreaManager is stopped.
	stopFunc context.CancelFunc
}

func NewRemoteCommonAreaManager(clusterSetID common.ClusterSetID, clusterID common.ClusterID) RemoteCommonAreaManager {
	klog.InfoS("Creating NewRemoteCommonAreaManager", "ClusterSet", clusterSetID)
	return &remoteCommonAreaManager{
		clusterSetID:      clusterSetID,
		clusterID:         clusterID,
		eventChan:         make(chan clusterEvent),
		remoteCommonAreas: make(map[common.ClusterID]RemoteCommonArea),
	}
}

/**
 * RemoteCommonAreaManager implementation
 */

func (r *remoteCommonAreaManager) Start() error {
	klog.InfoS("Starting RemoteCommonAreaManager", "ClusterSet", r.clusterSetID)
	stopCtx, stopFunc := context.WithCancel(context.Background())
	r.stopFunc = stopFunc

	// Start a Timer for every 5 seconds when leader election is
	// performed, if necessary.
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		for {
			select {
			case <-stopCtx.Done():
				klog.InfoS("Stopping RemoteCommonAreaManager", "ClusterSet", r.clusterSetID)
				close(r.eventChan)
				for _, rc := range r.remoteCommonAreas {
					rc.Stop()
				}
				r.remoteCommonAreas = nil
				// we are done.
				ticker.Stop()
				return
			case event := <-r.eventChan:
				// process the event.
				clusterID := event.remoteCommonArea.GetClusterID()

				if event.isAdd {
					if _, ok := r.remoteCommonAreas[clusterID]; ok {
						klog.Warningf("Cannot add RemoteCommonArea that is already present", "Cluster", clusterID)
					} else {
						klog.InfoS("Adding and starting RemoteCommonArea", "Cluster", clusterID)
						event.remoteCommonArea.Start()
						r.remoteCommonAreas[clusterID] = event.remoteCommonArea
					}
				} else {
					if rc, ok := r.remoteCommonAreas[clusterID]; !ok {
						klog.Warningf("Cannot remove RemoteCommonArea that is not present", "Cluster", clusterID)
					} else {
						klog.InfoS("Removing and stopping RemoteCommonArea", "Cluster", clusterID)
						rc.Stop()
					}
					delete(r.remoteCommonAreas, clusterID)
				}
			case <-ticker.C:
				r.RunLeaderElection()
			}
		}
	}()

	return nil
}

func (r *remoteCommonAreaManager) Stop() error {
	if r.stopFunc != nil {
		r.stopFunc()
		r.stopFunc = nil
	}
	return nil
}

func (r *remoteCommonAreaManager) AddRemoteCommonArea(remoteCommonArea RemoteCommonArea) {
	r.clusterSyncMap.Store(remoteCommonArea.GetClusterID(), remoteCommonArea)
	r.eventChan <- clusterEvent{
		isAdd:            true,
		remoteCommonArea: remoteCommonArea,
	}
}

func (r *remoteCommonAreaManager) RemoveRemoteCommonArea(remoteCommonArea RemoteCommonArea) {
	r.clusterSyncMap.Delete(remoteCommonArea.GetClusterID())
	r.eventChan <- clusterEvent{
		isAdd:            false,
		remoteCommonArea: remoteCommonArea,
	}
}

func (r *remoteCommonAreaManager) GetRemoteCommonAreas() map[common.ClusterID]RemoteCommonArea {
	clusters := make(map[common.ClusterID]RemoteCommonArea)
	r.clusterSyncMap.Range(func(k, v interface{}) bool {
		id := k.(common.ClusterID)
		clusters[id] = v.(RemoteCommonArea)
		return true
	})
	return clusters
}

func (r *remoteCommonAreaManager) GetElectedLeaderClusterID() common.ClusterID {
	defer r.mutex.Unlock()
	r.mutex.Lock()
	if r.electedLeaderCluster != nil {
		return r.electedLeaderCluster.GetClusterID()
	}
	return common.InvalidClusterID
}

func (r *remoteCommonAreaManager) GetLocalClusterID() common.ClusterID {
	return r.clusterID
}

func (r *remoteCommonAreaManager) GetMemberClusterStatues() []multiclusterv1alpha1.ClusterStatus {
	statues := make([]multiclusterv1alpha1.ClusterStatus, 0)

	r.clusterSyncMap.Range(func(k, v interface{}) bool {
		id := k.(common.ClusterID)
		statues = append(statues, multiclusterv1alpha1.ClusterStatus{
			ClusterID:  string(id),
			Conditions: v.(RemoteCommonArea).GetStatus(),
		})

		return true
	})

	return statues
}
