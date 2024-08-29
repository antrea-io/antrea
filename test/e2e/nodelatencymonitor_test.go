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
	skipIfHasWindowsNodes(t) // as the feature does not have official windows support

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	//  1: create the NodeLatencyMonitor CR with a 10s ping interval
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

	//  2: Poll until(5min) NodeLatencyStats are reported correctly
	ctx := context.Background()
	err = wait.PollImmediate(time.Second, 300*time.Second, func() (bool, error) {
		statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Logf("Error while listing NodeLatencyStats: %v", err)
			return false, err
		}

		latencyData := make(map[string][]int64)

		for _, item := range statsList.Items {
			for _, peerStat := range item.PeerNodeLatencyStats {
				for _, targetStat := range peerStat.TargetIPLatencyStats {
					latencyData[item.Name] = append(latencyData[item.Name], targetStat.LastMeasuredRTTNanoseconds)
				}
			}
		}

		t.Logf("%-20s %-20s %-20s %-20s", "NODE NAME", "NUM LATENCY ENTRIES", "AVG LATENCY", "MAX LATENCY")
		for nodeName, latencies := range latencyData {
			numEntries := len(latencies)
			if numEntries == 0 {
				continue
			}
			var sumLatency int64
			var maxLatency int64
			for _, latency := range latencies {
				sumLatency += latency
				if latency > maxLatency {
					maxLatency = latency
				}
			}
			avgLatency := float64(sumLatency) / float64(numEntries)
			t.Logf("%-20s %-20d %-20.6fms %-20.6fms", nodeName, numEntries, float64(avgLatency)/1e6, float64(maxLatency)/1e6)
		}

		if len(statsList.Items) == 0 {
			t.Logf("No NodeLatencyStats found, retrying...")
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("Failed to retrieve NodeLatencyStats: %v", err)
	}

	t.Logf("Successfully received NodeLatencyStats")

	//  3: Delete the NodeLatencyMonitor CR
	err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Delete(context.TODO(), "default", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete NodeLatencyMonitor CR: %v", err)
	}
	t.Logf("NodeLatencyMonitor CR deleted successfully.")
}
