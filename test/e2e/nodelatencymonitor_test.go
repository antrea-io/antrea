// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/stats/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

func TestNodeLatencyMonitor(t *testing.T) {
	skipIfFeatureDisabled(t, features.NodeLatencyMonitor, true, false)
	skipIfHasWindowsNodes(t) // as the feature does not have official Windows support

	data, err := setupTest(t)
	require.NoError(t, err, "Error when setting up test")

	defer teardownTest(t, data)

	var isDualStack bool
	if clusterInfo.podV4NetworkCIDR != "" && clusterInfo.podV6NetworkCIDR != "" {
		isDualStack = true
	}

	expectedTargetIPLatencyStats := 1
	if isDualStack {
		expectedTargetIPLatencyStats = 2
	}

	_, err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Create(context.TODO(), &crdv1alpha1.NodeLatencyMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: crdv1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: int32(10),
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create NodeLatencyMonitor CR")
	t.Logf("NodeLatencyMonitor CR created successfully.")

	defer func() {
		err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Delete(context.TODO(), "default", metav1.DeleteOptions{})
		require.NoError(t, err, "Failed to delete NodeLatencyMonitor CR")
		t.Logf("NodeLatencyMonitor CR deleted successfully.")
	}()
	previousTimes := make(map[string]map[string]metav1.Time)

	validateNodeLatencyStats := func(statsList *v1alpha1.NodeLatencyStatsList, initialPoll bool) (bool, error) {
		if len(statsList.Items) != clusterInfo.numNodes {
			t.Logf("Expected %d NodeLatencyStats, but found %d, retrying...", clusterInfo.numNodes, len(statsList.Items))
			return false, nil
		}

		for _, item := range statsList.Items {
			if len(item.PeerNodeLatencyStats) != clusterInfo.numNodes-1 {
				t.Logf("Expected %d PeerNodeLatencyStats for Node %s, but found %d, retrying...", clusterInfo.numNodes-1, item.Name, len(item.PeerNodeLatencyStats))
				return false, nil
			}

			for _, peerStat := range item.PeerNodeLatencyStats {
				if len(peerStat.TargetIPLatencyStats) != expectedTargetIPLatencyStats {
					t.Logf("Expected %d TargetIPLatencyStats for peer %s on Node %s, but found %d, retrying...",
						expectedTargetIPLatencyStats, peerStat.NodeName, item.Name, len(peerStat.TargetIPLatencyStats))
					return false, nil
				}

				for _, targetStat := range peerStat.TargetIPLatencyStats {
					if targetStat.LastMeasuredRTTNanoseconds <= 0 {
						t.Logf("Invalid RTT for peer %s reported by Node %s", peerStat.NodeName, item.Name)
						return false, nil
					}

					if initialPoll {
						if previousTimes[item.Name] == nil {
							previousTimes[item.Name] = make(map[string]metav1.Time)
						}
						previousTimes[item.Name][peerStat.NodeName] = targetStat.LastRecvTime
					} else {
						previousRecvTime, recvTimeExists := previousTimes[item.Name][peerStat.NodeName]
						if !recvTimeExists || !targetStat.LastRecvTime.After(previousRecvTime.Time) {
							t.Logf("LastRecvTime has not been updated for peer %s on Node %s", peerStat.NodeName, item.Name)
							return false, nil
						}
					}
				}
			}
		}
		return true, nil
	}

	err = wait.PollUntilContextTimeout(context.TODO(), time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		return validateNodeLatencyStats(statsList, true)
	})
	require.NoError(t, err, "Failed to validate initial NodeLatencyStats")

	err = wait.PollUntilContextTimeout(context.TODO(), time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		return validateNodeLatencyStats(statsList, false)
	})
	require.NoError(t, err, "Failed to validate updated NodeLatencyStats")

	t.Logf("Successfully received and validated NodeLatencyStats")

}
