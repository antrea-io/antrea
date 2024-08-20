package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// GetKubeconfigPath returns the path to the kubeconfig file used for connecting to the Kubernetes cluster.
func GetKubeconfigPath() (string, error) {
	// Check if the KUBECONFIG environment variable is set
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		// Default to the kubeconfig path in the user's home directory if not set
		kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}

	// Verify that the kubeconfig file exists
	if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
		return "", fmt.Errorf("kubeconfig file does not exist at path: %s", kubeconfig)
	}

	return kubeconfig, nil
}

// getAntreaClient returns a clientset for interacting with Antrea CRDs
func getAntreaClient(t *testing.T) *clientset.Clientset {
	kubeconfig, err := GetKubeconfigPath()
	failOnError(err, t)

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	failOnError(err, t)

	antreaClientset, err := clientset.NewForConfig(config)
	failOnError(err, t)
	return antreaClientset
}

// TestNodeLatencyMonitorCRUD tests the CRUD operations for NodeLatencyMonitor resources.
func TestNodeLatencyMonitorCRUD(t *testing.T) {
	clientset := getAntreaClient(t)
	crdClient := clientset.CrdV1alpha1().NodeLatencyMonitors()

	t.Run("Create NodeLatencyMonitor", func(t *testing.T) {
		latencyMonitor := &v1alpha1.NodeLatencyMonitor{
			ObjectMeta: v1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeLatencyMonitorSpec{
				PingIntervalSeconds: 10,
			},
		}

		createdMonitor, err := crdClient.Create(context.TODO(), latencyMonitor, v1.CreateOptions{})
		failOnError(err, t)
		assert.NotNil(t, createdMonitor)

		defer func() {
			err := crdClient.Delete(context.TODO(), "default", v1.DeleteOptions{})
			failOnError(err, t)
		}()
	})

	t.Run("Update NodeLatencyMonitor", func(t *testing.T) {
		createdMonitor, err := crdClient.Get(context.TODO(), "default", v1.GetOptions{})
		failOnError(err, t)

		createdMonitor.Spec.PingIntervalSeconds = 30
		updatedMonitor, err := crdClient.Update(context.TODO(), createdMonitor, v1.UpdateOptions{})
		failOnError(err, t)
		assert.NotNil(t, updatedMonitor)
		assert.Equal(t, int32(30), updatedMonitor.Spec.PingIntervalSeconds)
	})

	t.Run("Get NodeLatencyMonitor", func(t *testing.T) {
		fetchedMonitor, err := crdClient.Get(context.TODO(), "default", v1.GetOptions{})
		failOnError(err, t)
		assert.NotNil(t, fetchedMonitor)
	})

	t.Run("List NodeLatencyMonitors", func(t *testing.T) {
		monitorList, err := crdClient.List(context.TODO(), v1.ListOptions{})
		failOnError(err, t)
		assert.NotNil(t, monitorList)
		assert.Greater(t, len(monitorList.Items), 0)
	})

	t.Run("Delete NodeLatencyMonitor", func(t *testing.T) {
		err := crdClient.Delete(context.TODO(), "default", v1.DeleteOptions{})
		failOnError(err, t)

		_, err = crdClient.Get(context.TODO(), "default", v1.GetOptions{})
		assert.Error(t, err)
	})
}

// TestNodeLatencyMonitorWatch tests the watch functionality for NodeLatencyMonitor resources.
func TestNodeLatencyMonitorWatch(t *testing.T) {
	clientset := getAntreaClient(t)
	crdClient := clientset.CrdV1alpha1().NodeLatencyMonitors()

	t.Run("Watch NodeLatencyMonitor", func(t *testing.T) {
		opts := v1.ListOptions{
			Watch: true,
		}
		watcher, err := crdClient.Watch(context.TODO(), opts)
		failOnError(err, t)
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
	})
}
