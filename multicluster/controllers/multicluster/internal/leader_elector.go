package internal

import (
	"context"
	"math/rand"
	"time"

	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

/**
 * Lets consider a ClusterSet with 2 leader clusters and 1 member cluster
 *      Leader1        Leader2
 *			\         /
 *			 \       /
 *            -------
 *               ^
 *               |
 *            Member1
 * The member cluster connects to both leaders and performs Member Announce
 * to announce itself. And all resources from the Members are written into
 * Common Area of all Leader clusters. However resources are imported
 * only from an elected-leader cluster.
 *
 * This interface performs the election to pick an elected-leader
 * from the list of leader clusters in the ClusterSet spec.
 *
 * Leader Election picks an elected-leader among "connected" leaders
 * by choosing one randomly
 * The Member Cluster periodically writes MemberAnnounce CRD into every leader
 * cluster and is considered "connected" if it can successfully write so.
 * After leader election is done, the result is also used to update the
 * spec of the MemberAnnounce CRD during the next periodic write into
 * the leader's Common Area, so the leader knows it is the elected-leader
 * of this member (mainly for visibility and reporting)
 */
type LeaderElector interface {
	// start the leader elector, returns a cancelFunc to invoke when it must be stopped
	StartLeaderElection() context.CancelFunc
}

func (m *remoteClusterManager) StartLeaderElection() (context.CancelFunc, error) {
	stopCtx, stopFunc := context.WithCancel(context.Background())

	// Start a Timer for every 5 seconds when leader election is
	// performed, if necessary
	ticker := time.NewTicker(5 * time.Second)
	rand.Seed(time.Now().UnixNano())

	go func() {
		log := m.log.WithName("LeaderElector")
		log.Info("Starting leader election")
		for {
			select {
			case <-stopCtx.Done():
				log.Info("Stopping leader election")
				return
			case <-ticker.C:
				// 5 second timer has gone off, check if election must be done
				if !m.needElection {
					if m.electedLeaderCluster != nil && !m.electedLeaderCluster.IsConnected() {
						log.Info("Leader disconnected", "leader", m.electedLeaderCluster.GetClusterID())
						m.electedLeaderCluster = nil
					}
					if m.electedLeaderCluster == nil {
						// do we have any member that is connected?
						for _, cluster := range m.remoteClusters {
							if cluster.IsConnected() {
								m.needElection = true
							}
						}
					}
				}
				if m.needElection {
					m.DoLeaderElection()
				}
			}
		}
	}()

	return stopFunc, nil
}

func (m *remoteClusterManager) DoLeaderElection() {
	log := m.log.WithName("LeaderElector")

	// We have written member announce at least once to all remote clusters.
	// Pick one randomly if it is connected
	var connectedClusterIDs []common.ClusterID
	for _, cluster := range m.remoteClusters {
		if cluster.IsConnected() {
			connectedClusterIDs = append(connectedClusterIDs, cluster.GetClusterID())
		}
	}
	if len(connectedClusterIDs) > 0 {
		electedLeaderIndex := rand.Intn(len(connectedClusterIDs))
		// election complete
		electedLeaderClusterID := connectedClusterIDs[electedLeaderIndex]
		m.electedLeaderCluster = m.remoteClusters[electedLeaderClusterID]
		m.needElection = false
		log.Info("Election completed", "leader", electedLeaderClusterID)
		return
	}
	// couldnt elect a leader, will try next round
}
