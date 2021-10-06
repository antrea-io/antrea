package internal

import (
	"context"
	"sync"

	"github.com/go-logr/logr"

	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

type clusterEvent struct {
	isAdd         bool
	remoteCluster RemoteCluster
}

type RemoteClusterManager interface {
	// Start RemoteClusterManager on an event loop in a go routine
	Start() error
	// Stop RemoteClusterManager
	Stop() error
	// AddRemoteCluster adds a remote cluster to RemoteClusterManager.
	AddRemoteCluster(remoteCluster RemoteCluster)
	// RemoveRemoteCLuster removes a remote cluster from RemoteClusterManager.
	RemoveRemoteCluster(remoteCluster RemoteCluster)
	// GetRemteClusters returns all remote clusters
	GetRemoteClusters() map[common.ClusterID]RemoteCluster
	// GetElectedLeaderClusterID returns the leader remote cluster or INVALID_CLUSTER_ID if none elected
	GetElectedLeaderClusterID() common.ClusterID
	// GetLocalClusterID returns local cluster ID
	GetLocalClusterID() common.ClusterID
}

// The manager manages all leaders defined in the cluster set and manages common area access into them.
// It also interfaces with leader election to know the elected-leader from which resources
// must be monitored.
type remoteClusterManager struct {
	log logr.Logger

	clusterSetID common.ClusterSetID

	// map of all remote clusters to which we have access to their common area
	remoteClusters map[common.ClusterID]RemoteCluster

	// an elected leader in which certain operations need to be performed
	electedLeaderCluster RemoteCluster

	// set to true if we require leader election
	needElection bool

	// Local cluster ID
	clusterID common.ClusterID

	eventChan chan clusterEvent

	// Copy of remoteClusters for access from cluster set reconciler to avoid locking on remoteClusters
	clusterSyncMap sync.Map

	stopFunc context.CancelFunc
}

func NewRemoteClusterManager(clusterSetID common.ClusterSetID, log logr.Logger, clusterID common.ClusterID) RemoteClusterManager {
	return &remoteClusterManager{
		clusterSetID:   clusterSetID,
		clusterID:      clusterID,
		log:            log,
		eventChan:      make(chan clusterEvent),
		remoteClusters: make(map[common.ClusterID]RemoteCluster),
	}
}

/**
 * RemoteClusterManager implementation
 */

func (r *remoteClusterManager) Start() error {
	r.log.Info("Starting remote cluster manager for", "clusterset", r.clusterSetID)
	stopCtx, stopFunc := context.WithCancel(context.Background())
	r.StartLeaderElection()

	go func() {
		for {
			select {
			case <-stopCtx.Done():
				// we are done
				return
			case event := <-r.eventChan:
				// process event
				clusterID := event.remoteCluster.GetClusterID()

				if event.isAdd {
					if _, ok := r.remoteClusters[clusterID]; ok {
						r.log.Error(nil, "Cannot add remote cluster already in manager", "clusterID", clusterID)
					} else {
						event.remoteCluster.Start()
						r.remoteClusters[clusterID] = event.remoteCluster
					}
				} else {
					if rc, ok := r.remoteClusters[clusterID]; !ok {
						r.log.Error(nil, "Cannot remove remote cluster not in manager", "clusterID", clusterID)
					} else {
						rc.Stop()
					}
					delete(r.remoteClusters, clusterID)
				}
			}
		}
	}()

	r.stopFunc = stopFunc
	return nil
}

func (r *remoteClusterManager) Stop() error {
	if r.stopFunc != nil {
		r.stopFunc()
	}
	return nil
}

func (r *remoteClusterManager) AddRemoteCluster(remoteCluster RemoteCluster) {
	r.clusterSyncMap.Store(remoteCluster.GetClusterID(), remoteCluster)
	r.eventChan <- clusterEvent{
		isAdd:         true,
		remoteCluster: remoteCluster,
	}
}

func (r *remoteClusterManager) RemoveRemoteCluster(remoteCluster RemoteCluster) {
	r.clusterSyncMap.Store(remoteCluster.GetClusterID(), remoteCluster)
	r.eventChan <- clusterEvent{
		isAdd:         false,
		remoteCluster: remoteCluster,
	}
}

func (r *remoteClusterManager) GetRemoteClusters() map[common.ClusterID]RemoteCluster {
	clusters := make(map[common.ClusterID]RemoteCluster)
	r.clusterSyncMap.Range(func(k, v interface{}) bool {
		id := k.(common.ClusterID)
		clusters[id] = v.(RemoteCluster)
		return true
	})
	return clusters
}

func (r *remoteClusterManager) GetElectedLeaderClusterID() common.ClusterID {
	if r.electedLeaderCluster != nil {
		return r.electedLeaderCluster.GetClusterID()
	}
	return common.INVALID_CLUSTER_ID
}

func (r *remoteClusterManager) GetLocalClusterID() common.ClusterID {
	return r.clusterID
}
