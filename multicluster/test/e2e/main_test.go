// Copyright 2022 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process

package e2e

import (
	"flag"
	"log"
	"os"
	"path"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	agentconfig "antrea.io/antrea/pkg/config/agent"
)

const (
	antreaAgentConfigName string = "antrea-config"
	antreaAgentNamespace  string = "kube-system"
	antreaAgentConfName   string = "antrea-agent.conf"
)

// setupLogging creates a temporary directory to export the test logs if necessary. If a directory
// was provided by the user, it checks that the directory exists.
func (tOptions *TestOptions) setupLogging() func() {
	if tOptions.logsExportDir == "" {
		name, err := os.MkdirTemp("", "antrea-multicluster-test-")
		if err != nil {
			log.Fatalf("Error when creating temporary directory to export logs: %v", err)
		}
		log.Printf("Test logs (if any) will be exported under the '%s' directory", name)
		tOptions.logsExportDir = name
		// we will delete the temporary directory if no logs are exported
		return func() {
			if empty, _ := IsDirEmpty(name); empty {
				log.Printf("Removing empty logs directory '%s'", name)
				_ = os.Remove(name)
			} else {
				log.Printf("Logs exported under '%s', it is your responsibility to delete the directory when you no longer need it", name)
			}
		}
	}
	fInfo, err := os.Stat(tOptions.logsExportDir)
	if err != nil {
		log.Fatalf("Cannot stat provided directory '%s': %v", tOptions.logsExportDir, err)
	}
	if !fInfo.Mode().IsDir() {
		log.Fatalf("'%s' is not a valid directory", tOptions.logsExportDir)
	}
	// no-op cleanup function
	return func() {}
}

func testMain(m *testing.M) int {
	flag.StringVar(&testOptions.logsExportDir, "logs-export-dir", "", "Export directory for test logs")
	flag.StringVar(&testOptions.leaderClusterKubeConfigPath, "leader-cluster-kubeconfig-path", path.Join(homedir, ".kube", "leader"), "Kubeconfig Path of the leader cluster")
	flag.StringVar(&testOptions.eastClusterKubeConfigPath, "east-cluster-kubeconfig-path", path.Join(homedir, ".kube", "east"), "Kubeconfig Path of the east cluster")
	flag.StringVar(&testOptions.westClusterKubeConfigPath, "west-cluster-kubeconfig-path", path.Join(homedir, ".kube", "west"), "Kubeconfig Path of the west cluster")
	flag.BoolVar(&testOptions.enableGateway, "mc-gateway", false, "Run tests with Multicluster Gateway")
	flag.StringVar(&testOptions.providerName, "provider", "", "K8s test cluster provider")
	flag.Parse()

	cleanupLogging := testOptions.setupLogging()
	defer cleanupLogging()

	testData = &MCTestData{}
	log.Println("Creating K8s clientsets for ClusterSet")
	if err := testData.createClients(); err != nil {
		log.Fatalf("Error when creating K8s ClientSet: %v", err)
		return 1
	}
	if err := testData.initProviders(); err != nil {
		log.Fatalf("Error when initializing providers for ClusterSet: %v", err)
	}

	ret := m.Run()
	if ret != 0 {
		log.Println("Failed to run default Multi-cluster E2E tests")
		return ret
	}

	log.Println("Starting E2E test with WireGuard")
	for _, clusterName := range testData.clusters {
		if clusterName == leaderCluster {
			continue
		}
		if err := enableWireGuard(clusterName); err != nil {
			log.Fatalf("Error when enabling WireGuard encryption, error: %v", err)
		}
	}

	ret = m.Run()
	return ret
}

func enableWireGuard(clusterName string) error {
	data := testData.clusterTestDataMap[clusterName]
	configMap, err := data.GetConfigMap(antreaAgentNamespace, antreaAgentConfigName)
	if err != nil {
		return err
	}
	antreaAgentConfig := &agentconfig.AgentConfig{}
	if err := yaml.Unmarshal([]byte(configMap.Data[antreaAgentConfName]), antreaAgentConfig); err != nil {
		return err
	}
	antreaAgentConfig.Multicluster.TrafficEncryptionMode = "wireGuard"
	conf, err := yaml.Marshal(antreaAgentConfig)
	if err != nil {
		return err
	}
	configMap.Data[antreaAgentConfigName] = string(conf)
	if err := data.UpdateConfigMap(configMap); err != nil {
		return err
	}
	return data.RestartAntreaAgentPods(defaultTimeout)
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func TestConnectivity(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	if testOptions.enableGateway {
		initializeGateway(t, data)
		defer teardownGateway(t, data)

		// Sleep 5s to wait resource export/import process to finish resource
		// exchange, and data path realization.
		time.Sleep(5 * time.Second)
	}

	t.Run("TestMCService", func(t *testing.T) {
		defer tearDownForServiceExportsTest(t, data)
		initializeForServiceExportsTest(t, data)
		t.Run("Case=MCServiceConnectivity", func(t *testing.T) { testMCServiceConnectivity(t, data) })
		t.Run("Case=ScaleDownMCServiceEndpoints", func(t *testing.T) { testScaleDownMCServiceEndpoints(t, data) })
		t.Run("Case=ANNPToServices", func(t *testing.T) { testANNPToServices(t, data) })
		t.Run("Case=StretchedNetworkPolicy", func(t *testing.T) { testStretchedNetworkPolicy(t, data) })
		t.Run("Case=StretchedNetworkPolicyReject", func(t *testing.T) { testStretchedNetworkPolicyReject(t, data) })
		t.Run("Case=StretchedNetworkPolicyUpdatePod", func(t *testing.T) { testStretchedNetworkPolicyUpdatePod(t, data) })
		t.Run("Case=StretchedNetworkPolicyUpdateNS", func(t *testing.T) { testStretchedNetworkPolicyUpdateNS(t, data) })
		t.Run("Case=StretchedNetworkPolicyUpdatePolicy", func(t *testing.T) { testStretchedNetworkPolicyUpdatePolicy(t, data) })
	})

	t.Run("TestAntreaPolicy", func(t *testing.T) {
		defer tearDownForPolicyTest()
		initializeForPolicyTest(t, data)
		t.Run("Case=CopySpanNSIsolation", func(t *testing.T) { testAntreaPolicyCopySpanNSIsolation(t, data) })
		t.Run("Case=CrossClusterNSIsolation", func(t *testing.T) { testAntreaPolicyCrossClusterNSIsolation(t, data) })
	})
	// Wait 5 seconds to let both member and leader controllers clean up all resources,
	// otherwise, Namespace deletion may be stuck in terminating status.
	time.Sleep(5 * time.Second)
}
