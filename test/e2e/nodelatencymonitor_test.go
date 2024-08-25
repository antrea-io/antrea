package e2e

import (
	"context"
	"math/rand"
	"testing"
	"time"

	v1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"

	"antrea.io/antrea/pkg/features"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	nodeLatencyMonitorName = "default"
)

// pingIntervalSeconds between 30 and 50
func generatePingInterval() int32 {
	return int32(rand.Intn(21) + 30)
}

func TestNodeLatencyMonitor(t *testing.T) {

	skipIfFeatureDisabled(t, features.NodeLatencyMonitor, true, false)
	skipIfHasWindowsNodes(t) // as it does not have offitial windows support

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testEnableLatencyProbes", func(t *testing.T) { testEnableLatencyProbes(t, data) })
	t.Run("testRetrieveLatencyStats", func(t *testing.T) { testRetrieveLatencyStats(t, data) })
	t.Run("testUpdatePingInterval", func(t *testing.T) { testUpdatePingInterval(t, data) })
	t.Run("testDisableLatencyProbes", func(t *testing.T) { testDisableLatencyProbes(t, data) })
}

func createOrUpdateNodeLatencyMonitorCR(t *testing.T, data *TestData, interval int32) {
	nlm := &v1alpha1.NodeLatencyMonitor{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeLatencyMonitorName,
		},
		Spec: v1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: interval,
		},
	}

	existingNLM, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nlm.Name, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {

			_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Create(context.TODO(), nlm, v1.CreateOptions{})
			if err != nil {
				t.Fatalf("Failed to create NodeLatencyMonitor CR: %v", err)
			}
			t.Logf("NodeLatencyMonitor CR created successfully.")
		}
	} else {

		nlm.ResourceVersion = existingNLM.ResourceVersion
		_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Update(context.TODO(), nlm, v1.UpdateOptions{})
		if err != nil {
			t.Fatalf("Failed to update NodeLatencyMonitor CR: %v", err)
		}
		t.Logf("NodeLatencyMonitor CR updated successfully.")
	}
}

func testEnableLatencyProbes(t *testing.T, data *TestData) {
	pingInterval := int32(60)

	createOrUpdateNodeLatencyMonitorCR(t, data, pingInterval)
	_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			t.Fatalf("NodeLatencyMonitor CR not found after creation: %v", err)
		} else {
			t.Fatalf("Unable to get NodeLatencyMonitor CR: %v", err)
		}
	}

	t.Log("Latency probes are confirmed to be enabled.")
}

func testDisableLatencyProbes(t *testing.T, data *TestData) {

	_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			t.Logf("NodeLatencyMonitor CR does not exist, no need to delete.")
			return
		}
		t.Fatalf("Error when checking for NodeLatencyMonitor CR: %v", err)
	}

	err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Delete(context.TODO(), nodeLatencyMonitorName, v1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete NodeLatencyMonitor CR: %v", err)
	}
	t.Logf("Latency probes are confirmed to be disabled..")
}

func testUpdatePingInterval(t *testing.T, data *TestData) {
	nlm, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			t.Logf("NodeLatencyMonitor CR not found, creating a new one.")
			pingInterval := int32(60)
			createOrUpdateNodeLatencyMonitorCR(t, data, pingInterval)
			nlm, err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
			if err != nil {
				t.Fatalf("Failed to retrieve NodeLatencyMonitor CR after creation: %v", err)
			}
		} else {
			t.Fatalf("Failed to retrieve NodeLatencyMonitor CR: %v", err)
		}
	}

	// Update the ping interval
	newInterval := generatePingInterval()
	nlm.Spec.PingIntervalSeconds = newInterval
	_, err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Update(context.TODO(), nlm, v1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update NodeLatencyMonitor CR: %v", err)
	}

	t.Logf("Ping interval updated successfully to %d seconds.", newInterval)
}

func testRetrieveLatencyStats(t *testing.T, data *TestData) {

	summary := &statsv1alpha1.NodeLatencyStats{
		ObjectMeta: v1.ObjectMeta{Name: "kind-worker"},
		PeerNodeLatencyStats: []statsv1alpha1.PeerNodeLatencyStats{
			{
				NodeName: "kind-control-plane",
				TargetIPLatencyStats: []statsv1alpha1.TargetIPLatencyStats{
					{
						LastMeasuredRTTNanoseconds: 5837000,
						LastRecvTime:               v1.Time{Time: time.Now().Add(-time.Minute)},
						LastSendTime:               v1.Time{Time: time.Now().Add(-time.Minute)},
						TargetIP:                   "10.10.0.1",
					},
				},
			},
			{
				NodeName: "kind-worker2",
				TargetIPLatencyStats: []statsv1alpha1.TargetIPLatencyStats{
					{
						LastMeasuredRTTNanoseconds: 4704000,
						LastRecvTime:               v1.Time{Time: time.Now().Add(-time.Minute)},
						LastSendTime:               v1.Time{Time: time.Now().Add(-time.Minute)},
						TargetIP:                   "10.10.2.1",
					},
				},
			},
		},
	}

	ctx := context.Background()

	_, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().Create(ctx, summary, v1.CreateOptions{})
	require.NoError(t, err)

	err = wait.PollImmediate(time.Second, 15*time.Second, func() (bool, error) {
		statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(ctx, v1.ListOptions{})
		if err != nil {
			t.Logf("Error while listing NodeLatencyStats: %v", err)
			return false, err
		}
		if len(statsList.Items) == 0 {
			t.Logf("No NodeLatencyStats found, retrying...%v", statsList)
			return false, nil
		}

		for _, item := range statsList.Items {
			t.Logf("NodeLatencyStats found for node: %s", item.Name)
		}
		return true, nil
	})

	if err != nil {
		t.Fatalf("Failed to retrieve NodeLatencyStats: %v", err)
	}

	statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(ctx, v1.ListOptions{})
	require.NoError(t, err)
	assert.Greater(t, len(statsList.Items), 0, "Expected at least one NodeLatencyStats item")

	found := false
	for _, item := range statsList.Items {
		if item.Name == "kind-worker" {
			found = true

			assert.Len(t, item.PeerNodeLatencyStats, 2, "Expected 2 PeerNodeLatencyStats items")

			break
		}
	}
	assert.True(t, found, "NodeLatencyStats for 'kind-worker' not found")
	t.Logf("Successfully received NodeLatencyStats")
}
