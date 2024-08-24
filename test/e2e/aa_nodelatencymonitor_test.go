// --- PASS: TestNodeLatencyMonitor/testEnableLatencyProbes (0.00s)
// --- FAIL: TestNodeLatencyMonitor/testRetrieveLatencyStats (60.01s)
// --- PASS: TestNodeLatencyMonitor/testUpdatePingInterval (0.02s)
// --- PASS: TestNodeLatencyMonitor/testDisableLatencyProbes (0.01s)
package e2e

import (
	"context"
	"testing"
	"time"

	v1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	nodeLatencyMonitorName = "default"
	nodeLatencyMonitorNS   = "kube-system"
	pingIntervalSeconds    = 50
)

func TestNodeLatencyMonitor(t *testing.T) {
	skipIfNotRequired(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Failed to set up clients: %v", err)
	}
	defer teardownTest(t, data)

	// Create or update the NodeLatencyMonitor CR before running tests
	createOrUpdateNodeLatencyMonitorCR(t, data)

	// Run each test sequentially to identify which test is failing
	t.Run("testEnableLatencyProbes", func(t *testing.T) {
		testEnableLatencyProbes(t, data)
	})
	t.Run("testRetrieveLatencyStats", func(t *testing.T) {
		testRetrieveLatencyStats(t, data)
	})
	t.Run("testUpdatePingInterval", func(t *testing.T) {
		testUpdatePingInterval(t, data)
	})
	t.Run("testDisableLatencyProbes", func(t *testing.T) {
		testDisableLatencyProbes(t, data)
	})
}

func createOrUpdateNodeLatencyMonitorCR(t *testing.T, data *TestData) {
	nlm := &v1alpha1.NodeLatencyMonitor{
		ObjectMeta: v1.ObjectMeta{
			Name:      nodeLatencyMonitorName,
			Namespace: nodeLatencyMonitorNS,
		},
		Spec: v1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: pingIntervalSeconds,
		},
	}

	// Try to get the existing NodeLatencyMonitor CR
	existingNLM, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nlm.Name, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// CR does not exist, so create it
			_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Create(context.TODO(), nlm, v1.CreateOptions{})
			if err != nil {
				t.Fatalf("Failed to create NodeLatencyMonitor CR: %v", err)
			}
		} else {
			// Some other error occurred while getting the CR
			t.Fatalf("Failed to get NodeLatencyMonitor CR: %v", err)
		}
	} else {
		// CR exists, so update it
		nlm.ResourceVersion = existingNLM.ResourceVersion
		_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Update(context.TODO(), nlm, v1.UpdateOptions{})
		if err != nil {
			t.Fatalf("Failed to update NodeLatencyMonitor CR: %v", err)
		}
	}

	// Ensure the CR is in the desired state
	waitForNodeLatencyMonitor(t, data)
}

func testEnableLatencyProbes(t *testing.T, data *TestData) {
	// No need to create a new CR, as it's already created in createOrUpdateNodeLatencyMonitorCR
	waitForLatencyProbesEnabled(t, data)
}

func testDisableLatencyProbes(t *testing.T, data *TestData) {
	err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Delete(context.TODO(), nodeLatencyMonitorName, v1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete NodeLatencyMonitor CR: %v", err)
	}

	waitForLatencyProbesDisabled(t, data)
}

func testUpdatePingInterval(t *testing.T, data *TestData) {
	nlm, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to retrieve NodeLatencyMonitor CR: %v", err)
	}

	newInterval := pingIntervalSeconds + 5
	nlm.Spec.PingIntervalSeconds = int32(newInterval)
	_, err = data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Update(context.TODO(), nlm, v1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update NodeLatencyMonitor CR: %v", err)
	}

	waitForPingIntervalUpdate(t, data, int32(newInterval))
}

func testRetrieveLatencyStats(t *testing.T, data *TestData) {
	err := wait.PollImmediate(time.Second, 60*time.Second, func() (bool, error) {
		// Attempt to list NodeLatencyStats
		statsList, err := data.crdClient.StatsV1alpha1().NodeLatencyStats().List(context.TODO(), v1.ListOptions{})
		if err != nil {
			// Retry if there's an error
			return false, err
		}
		if len(statsList.Items) == 0 {
			// Retry if no stats are retrieved yet
			return false, nil
		}
		return true, nil
	})

	// Fail the test if stats couldn't be retrieved within the timeout
	if err != nil {
		t.Fatalf("Failed to retrieve NodeLatencyStats: %v", err)
	}
}

func waitForNodeLatencyMonitor(t *testing.T, data *TestData) {
	err := wait.PollImmediate(time.Second, 60*time.Second, func() (bool, error) {
		_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
		if err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("NodeLatencyMonitor CR not found: %v", err)
	}
}

func waitForLatencyProbesEnabled(t *testing.T, data *TestData) {
	err := wait.PollImmediate(time.Second, 60*time.Second, func() (bool, error) {
		nlm, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
		if err != nil {
			return false, err
		}
		return nlm.Spec.PingIntervalSeconds == pingIntervalSeconds, nil
	})
	if err != nil {
		t.Fatalf("Latency probes were not enabled: %v", err)
	}
}

func waitForLatencyProbesDisabled(t *testing.T, data *TestData) {
	err := wait.PollImmediate(time.Second, 60*time.Second, func() (bool, error) {
		_, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
		return err != nil && errors.IsNotFound(err), nil
	})
	if err != nil {
		t.Fatalf("Latency probes were not disabled: %v", err)
	}
}

func waitForPingIntervalUpdate(t *testing.T, data *TestData, expectedInterval int32) {
	err := wait.PollImmediate(time.Second, 60*time.Second, func() (bool, error) {
		nlm, err := data.crdClient.CrdV1alpha1().NodeLatencyMonitors().Get(context.TODO(), nodeLatencyMonitorName, v1.GetOptions{})
		if err != nil {
			return false, err
		}
		return nlm.Spec.PingIntervalSeconds == expectedInterval, nil
	})
	if err != nil {
		t.Fatalf("Ping interval was not updated: %v", err)
	}
}
