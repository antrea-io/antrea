package e2e

import (
	"flag"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"
)

func setupTest(t *testing.T) (*TestData, error) {
	data := &TestData{}
	t.Logf("Creating k8s clientset")
	if err := data.createClient(); err != nil {
		return nil, err
	}
	t.Logf("Creating '%s' k8s namespace", testNamespace)
	if err := data.createTestNamespace(); err != nil {
		return nil, err
	}
	t.Logf("Applying OKN YAML")
	if err := data.deployOKN(); err != nil {
		return nil, err
	}
	t.Logf("Waiting for all OKN DameonSet pods")
	if err := data.waitForOKNDaemonSetPods(defaultTimeout); err != nil {
		return nil, err
	}
	// TODO: CoreDNS keeps crashing at the moment, even when OKN is running fine
	// t.Logf("Checking CoreDNS deployment")
	// if err := data.checkCoreDNSPods(defaultTimeout); err != nil {
	// 	return nil, err
	// }
	return data, nil
}

func teardownTest(t *testing.T, data *TestData) {
	t.Logf("Deleting '%s' k8s namespace", testNamespace)
	if err := data.deleteTestNamespace(defaultTimeout); err != nil {
		t.Logf("Error when tearing down test: %v", err)
	}
}

func deletePodWrapper(t *testing.T, data *TestData, name string) {
	t.Logf("Deleting Pod '%s'", name)
	if err := data.deletePod(name); err != nil {
		t.Logf("Error when deleting Pod: %v", err)
	}
}

// A "no-op" test that simply performs setup and teardown.
func TestDeploy(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
}

// This test is meant to verify that OKN allocates IP addresses properly to new Pods. It does this
// by deploying a busybox Pod, then waiting for the k8s apiserver to report the new IP address for
// that Pod, and finally verifying that the IP address is in the Pod Network CIDR for the cluster.
func TestPodAssignIP(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	podName := randPodName("test-pod-")

	t.Logf("Creating a busybox test Pod")
	if err := data.createBusyboxPod(podName); err != nil {
		t.Fatalf("Error when creating busybox test pod: %v", err)
	}
	defer deletePodWrapper(t, data, podName)

	t.Logf("Checking Pod networking")
	if podIP, err := data.podWaitForIP(defaultTimeout, podName); err != nil {
		t.Errorf("Error when waiting for Pod IP: %v", err)
	} else {
		t.Logf("Pod IP is '%s'", podIP)
		isValid, err := validatePodIP(clusterInfo.podNetworkCIDR, podIP)
		if err != nil {
			t.Errorf("Error when trying to validate Pod IP: %v", err)
		} else if !isValid {
			t.Errorf("Pod IP is not in the expected Pod Network CIDR")
		} else {
			t.Logf("Pod IP is valid!")
		}
	}
}

// This test verifies that OKN Pods can terminate gracefully.
func TestOKNGracefulExit(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	var gracePeriodSeconds int64 = 60
	t.Logf("Deleting one OKN Pod")
	if timeToDelete, err := data.deleteOneOKNPod(gracePeriodSeconds, defaultTimeout); err != nil {
		t.Fatalf("Error when deleting OKN Pod: %v", err)
	} else if timeToDelete > 20*time.Second {
		t.Errorf("OKN Pod took too long to delete: %v", timeToDelete)
	}
	// at the moment we only check that the Pod terminates in a reasonnable amout of time (less
	// than the grace period), which means that all containers "honor" the SIGTERM signal
	// TODO: ideally we would be able to also check the exit code but it may not be possible
}

func TestMain(m *testing.M) {
	flag.StringVar(&testOptions.providerName, "provider", "vagrant", "k8s test cluster provider")
	flag.StringVar(&testOptions.providerConfigPath, "provider-cfg-path", "", "Optional config file for provider")
	flag.Parse()

	if err := initProvider(); err != nil {
		log.Fatalf("Error when initializing provider: %v", err)
	}

	log.Println("Collecting information about k8s cluster")
	if err := collectClusterInfo(); err != nil {
		log.Fatalf("Error when collecting information about k8s cluster: %v", err)
	} else {
		log.Printf("Pod network: '%s'", clusterInfo.podNetworkCIDR)
		log.Printf("Num nodes: %d", clusterInfo.numNodes)
	}

	rand.Seed(time.Now().UnixNano())
	os.Exit(m.Run())
}
