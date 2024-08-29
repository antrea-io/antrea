package e2e

import (
	"context"
	"testing"
	"time"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestNodeLatencyMonitor(t *testing.T) {
	skipIfFeatureDisabled(t, features.NodeLatencyMonitor, true, false)
	skipIfHasWindowsNodes(t) // as the feature does not have official Windows support

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	//  1: Create the NodeLatencyMonitor CR with a 10s ping interval
	_, err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Create(context.TODO(), &crdv1alpha1.NodeLatencyMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: crdv1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: int32(10),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create NodeLatencyMonitor CR: %v", err)
	}
	t.Logf("NodeLatencyMonitor CR created successfully.")

	//  2: First PollImmediate call (30s timeout)
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

		for _, item := range statsList.Items {
			if len(item.PeerNodeLatencyStats) == 0 {
				t.Logf("Node %s has no PeerNodeLatencyStats", item.Name)
				return false, nil
			}
			for _, peerStat := range item.PeerNodeLatencyStats {
				if len(peerStat.TargetIPLatencyStats) == 0 {
					t.Logf("Peer %s has no TargetIPLatencyStats", peerStat.NodeName)
					return false, nil
				}
				for _, targetStat := range peerStat.TargetIPLatencyStats {
					if targetStat.LastMeasuredRTTNanoseconds <= 0 {
						t.Logf("Invalid(negetive) RTT for peer %s on node %s", peerStat.NodeName, item.Name)
						return false, nil
					}
				}
			}
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("Failed to retrieve initial NodeLatencyStats: %v", err)
	}

	//  3: Second PollImmediate call (30s timeout)
	var previousSendTime, previousRecvTime metav1.Time

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

		for _, item := range statsList.Items {
			for _, peerStat := range item.PeerNodeLatencyStats {
				for _, targetStat := range peerStat.TargetIPLatencyStats {
					// Check that LastSendTime and LastRecvTime are not mising
					if targetStat.LastSendTime.IsZero() || targetStat.LastRecvTime.IsZero() {
						t.Logf("Missing timestamps for peer %s on node %s", peerStat.NodeName, item.Name)
						return false, nil
					}
					// Check if timestamps have changed
					if previousSendTime.Equal(&targetStat.LastSendTime) && previousRecvTime.Equal(&targetStat.LastRecvTime) {
						t.Logf("Timestamps have not been updated for peer %s on node %s", peerStat.NodeName, item.Name)
						return false, nil
					}
					previousSendTime = targetStat.LastSendTime
					previousRecvTime = targetStat.LastRecvTime
				}
			}
		}

		return true, nil
	})
	t.Logf("Successfully received and validated NodeLatencyStats")

	//  4: Delete the NodeLatencyMonitor CR
	err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Delete(context.TODO(), "default", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete NodeLatencyMonitor CR: %v", err)
	}
	t.Logf("NodeLatencyMonitor CR deleted successfully.")
}
