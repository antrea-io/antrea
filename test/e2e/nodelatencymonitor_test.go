package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/stats/v1alpha1"
	"antrea.io/antrea/pkg/features"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestNodeLatencyMonitor(t *testing.T) {
	skipIfFeatureDisabled(t, features.NodeLatencyMonitor, true, false)
	skipIfHasWindowsNodes(t) // as the feature does not have official Windows support

	data, err := setupTest(t)
	require.NoError(t, err, "Error when setting up test")

	defer teardownTest(t, data)

	nodes, err := data.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	require.NoError(t, err, "Failed to list nodes")

	var isDualStack bool
	for _, node := range nodes.Items {
		if node.Spec.PodCIDR != "" && strings.Contains(node.Spec.PodCIDR, ":") {
			isDualStack = true
			break
		}
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

	validateNodeLatencyStats := func(statsList *v1alpha1.NodeLatencyStatsList, initialPoll bool, previousTimes map[string]map[string]metav1.Time) (bool, error) {
		if len(statsList.Items) != len(nodes.Items) {
			t.Logf("Expected %d NodeLatencyStats, but found %d, retrying...", len(nodes.Items), len(statsList.Items))
			return false, nil
		}

		for _, item := range statsList.Items {
			if len(item.PeerNodeLatencyStats) != len(nodes.Items)-1 {
				t.Logf("Expected %d PeerNodeLatencyStats for node %s, but found %d, retrying...", len(nodes.Items), item.Name, len(item.PeerNodeLatencyStats))
				return false, nil
			}

			for _, peerStat := range item.PeerNodeLatencyStats {
				if len(peerStat.TargetIPLatencyStats) != expectedTargetIPLatencyStats {
					t.Logf("Expected %d TargetIPLatencyStats for peer %s on node %s, but found %d, retrying...",
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
						previousTimes[item.Name][peerStat.NodeName] = targetStat.LastSendTime
					} else {
						previousSendTime, sendTimeExists := previousTimes[item.Name][peerStat.NodeName]
						if !sendTimeExists || previousSendTime.Equal(&targetStat.LastSendTime) {
							t.Logf("LastSendTime has not been updated for peer %s on node %s", peerStat.NodeName, item.Name)
							return false, nil
						}
					}
				}
			}
		}
		return true, nil
	}

	previousTimes := make(map[string]map[string]metav1.Time)
	err = wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			t.Logf("Error while listing NodeLatencyStats: %v", err)
			return false, err
		}

		if len(statsList.Items) == 0 {
			t.Logf("No NodeLatencyStats found, retrying...")
			return false, nil
		}

		valid, validateErr := validateNodeLatencyStats(statsList, true, previousTimes)
		if !valid {
			return false, validateErr
		}
		return true, nil
	})
	require.NoError(t, err, "Failed to retrieve initial NodeLatencyStats")

	err = wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			t.Logf("Error while listing NodeLatencyStats: %v", err)
			return false, err
		}

		if len(statsList.Items) == 0 {
			t.Logf("No NodeLatencyStats found, retrying...")
			return false, nil
		}

		valid, validateErr := validateNodeLatencyStats(statsList, false, previousTimes)
		if !valid {
			return false, validateErr
		}
		return true, nil
	})
	require.NoError(t, err, "Failed to validate NodeLatencyStats after update")

	t.Logf("Successfully received and validated NodeLatencyStats")

	err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Delete(context.TODO(), "default", metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete NodeLatencyMonitor CR")
	t.Logf("NodeLatencyMonitor CR deleted successfully.")
}
