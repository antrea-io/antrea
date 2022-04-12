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
	"crypto/rand"
	"math/big"

	"k8s.io/klog/v2"

	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

/**
 * Lets consider a ClusterSet with 2 leader clusters and 1 member cluster.
 *  Leader1        Leader2
 *       \         /
 *        \       /
 *         -------
 *            ^
 *            |
 *         Member1
 * The member cluster connects to both leaders. It writes MemberClusterAnnounce
 * and other resources into CommonArea of both leaders. However, resources
 * are imported only from an elected-leader cluster.
 *
 * This interface performs the election to pick an elected-leader
 * from the list of leader clusters in the ClusterSet spec.
 *
 * Leader election picks an elected-leader among "connected" leaders
 * by choosing one randomly.
 * The member cluster periodically writes MemberClusterAnnounce into every leader
 * cluster and is considered "connected" if it can successfully write so.
 * After leader election is done, the result is also used to update the
 * spec of MemberClusterAnnounce during the next periodic write into the
 * leader's CommonArea, so the leader knows it is the elected-leader of this
 * member (mainly for visibility and reporting).
 */

type LeaderElector interface {
	// RunLeaderElection runs leader election. It is invoked periodically on a timer.
	RunLeaderElection()
}

func (r *remoteCommonAreaManager) RunLeaderElection() {
	if !r.needElection {
		if r.electedLeaderCluster != nil {
			if !r.electedLeaderCluster.IsConnected() {
				klog.InfoS("Disconnected leader", "Cluster",
					r.electedLeaderCluster.GetClusterID())
				r.setElectedLeader(nil)
			}
		}
		if r.electedLeaderCluster == nil {
			// Do we have any member that is connected?
			for _, cluster := range r.remoteCommonAreas {
				if cluster.IsConnected() {
					r.needElection = true
				}
			}
		}
	}
	if r.needElection {
		klog.InfoS("Perform leader election")
		r.doLeaderElection()
	}
}

func (r *remoteCommonAreaManager) doLeaderElection() {
	// We have written MemberClusterAnnounce at least once to all RemoteCommonArea.
	// Pick one randomly if it is connected.
	var connectedClusterIDs []common.ClusterID
	for id, cluster := range r.remoteCommonAreas {
		if cluster.IsConnected() {
			klog.InfoS("Election: leader is connected", "Cluster", id)
			connectedClusterIDs = append(connectedClusterIDs, cluster.GetClusterID())
		} else {
			klog.InfoS("Election: leader is not connected", "Cluster", id)
		}
	}
	if len(connectedClusterIDs) > 0 {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(connectedClusterIDs))))
		if err != nil {
			klog.ErrorS(err, "Unable to perform leader election")
			return
		}
		electedLeaderIndex := nBig.Int64()
		// election complete
		electedLeaderClusterID := connectedClusterIDs[electedLeaderIndex]
		klog.InfoS("Election completed", "ElectedLeader", electedLeaderClusterID)
		r.setElectedLeader(r.remoteCommonAreas[electedLeaderClusterID])
		r.needElection = false
		return
	}
	// Couldn't elect a leader, will try next interval.
}

func (r *remoteCommonAreaManager) setElectedLeader(cluster RemoteCommonArea) {
	defer r.mutex.Unlock()
	r.mutex.Lock()

	if r.electedLeaderCluster == cluster {
		return
	}

	if r.electedLeaderCluster != nil {
		r.electedLeaderCluster.StopWatching()
	}
	r.electedLeaderCluster = cluster
	if cluster != nil {
		if err := cluster.StartWatching(); err != nil {
			klog.ErrorS(err, "Failed to start watching events")
		}
	}
}
