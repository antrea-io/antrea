package v1alpha1_test

import (
	"context"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// getAntreaClient returns a clientset for interacting with Antrea CRDs
func getAntreaClient() *clientset.Clientset {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	kubeconfig := filepath.Join(user.HomeDir, ".kube", "config")

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	antreaClientset, err := clientset.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	return antreaClientset
}

// TestNodeLatencyMonitorCRUD tests the CRUD operations for NodeLatencyMonitor resources.
// It performs the following actions:
// 1. Creates a new NodeLatencyMonitor resource.
// 2. Updates the created resource to change its PingIntervalSeconds.
// 3. Retrieves the updated resource to ensure the changes were applied.
// 4. Lists all NodeLatencyMonitor resources and verifies the count.
// 5. Deletes the created resource and ensures the deletion was successful.
func TestNodeLatencyMonitorCRUD(t *testing.T) {
	clientset := getAntreaClient()
	crdClient := clientset.CrdV1alpha1().NodeLatencyMonitors()

	// Test Create
	latencyMonitor := &v1alpha1.NodeLatencyMonitor{
		ObjectMeta: v1.ObjectMeta{
			Name: "default",
		},
		Spec: v1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: 10,
		},
	}

	createdMonitor, err := crdClient.Create(context.TODO(), latencyMonitor, v1.CreateOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, createdMonitor)

	// Test Update
	createdMonitor.Spec.PingIntervalSeconds = 30
	updatedMonitor, err := crdClient.Update(context.TODO(), createdMonitor, v1.UpdateOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, updatedMonitor)
	assert.Equal(t, int32(30), updatedMonitor.Spec.PingIntervalSeconds)

	// Test Get
	fetchedMonitor, err := crdClient.Get(context.TODO(), "default", v1.GetOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, fetchedMonitor)

	// Test List
	monitorList, err := crdClient.List(context.TODO(), v1.ListOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, monitorList)
	assert.Greater(t, len(monitorList.Items), 0)

	// Test Delete
	err = crdClient.Delete(context.TODO(), "default", v1.DeleteOptions{})
	assert.NoError(t, err)

	// Ensure deletion was successful
	_, err = crdClient.Get(context.TODO(), "default", v1.GetOptions{})
	assert.Error(t, err)
}

// TestNodeLatencyMonitorWatch tests the watch functionality for NodeLatencyMonitor resources.
// It performs the following actions:
// 1. Starts watching NodeLatencyMonitor resources.
// 2. Receives and logs events related to NodeLatencyMonitor resources.
// 3. Times out after 10 seconds to ensure the watch functionality is working.

func TestNodeLatencyMonitorWatch(t *testing.T) {
	clientset := getAntreaClient()
	crdClient := clientset.CrdV1alpha1().NodeLatencyMonitors()

	opts := v1.ListOptions{
		Watch: true,
	}
	watcher, err := crdClient.Watch(context.TODO(), opts)
	assert.NoError(t, err)
	defer watcher.Stop()

	timeout := time.After(10 * time.Second)
	for {
		select {
		case event := <-watcher.ResultChan():
			assert.NotNil(t, event)
			t.Logf("Received event: %v", event)
		case <-timeout:
			t.Log("Timed out waiting for watch events")
			return
		}
	}
}
