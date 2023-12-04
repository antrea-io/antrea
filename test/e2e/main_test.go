// Copyright 2019 Antrea Authors
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

package e2e

import (
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
)

// setupLogging creates a temporary directory to export the test logs if necessary. If a directory
// was provided by the user, it checks that the directory exists.
func (tOptions *TestOptions) setupLogging() func() {
	if tOptions.logsExportDir == "" {
		name, err := os.MkdirTemp("", "antrea-test-")
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

// setupCoverage checks if the directory provided by the user exists.
func (tOptions *TestOptions) setupCoverage(data *TestData) func() {
	if tOptions.coverageDir != "" {
		fInfo, err := os.Stat(tOptions.coverageDir)
		if err != nil {
			log.Fatalf("Cannot stat provided directory '%s': %v", tOptions.coverageDir, err)
		}
		if !fInfo.Mode().IsDir() {
			log.Fatalf("'%s' is not a valid directory", tOptions.coverageDir)
		}

	}
	// cpNodeCoverageDir is a directory on the control-plane Node, where tests can deposit test
	// coverage data.
	log.Printf("Creating directory '%s' on Node '%s'\n", cpNodeCoverageDir, controlPlaneNodeName())
	rc, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("mkdir -p %s", cpNodeCoverageDir))
	if err != nil || rc != 0 {
		log.Fatalf("Failed to create directory '%s' on control-plane Node", cpNodeCoverageDir)
	}
	return func() {
		log.Printf("Removing directory '%s' on Node '%s'\n", cpNodeCoverageDir, controlPlaneNodeName())
		// best effort
		data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("rm -rf %s", cpNodeCoverageDir))
	}

}

// testMain is meant to be called by TestMain and enables the use of defer statements.
func testMain(m *testing.M) int {
	flag.StringVar(&testOptions.providerName, "provider", "vagrant", "K8s test cluster provider")
	flag.StringVar(&testOptions.providerConfigPath, "provider-cfg-path", "", "Optional config file for provider")
	flag.StringVar(&testOptions.logsExportDir, "logs-export-dir", "", "Export directory for test logs")
	flag.BoolVar(&testOptions.logsExportOnSuccess, "logs-export-on-success", false, "Export logs even when a test is successful")
	flag.BoolVar(&testOptions.withBench, "benchtest", false, "Run tests include benchmark tests")
	flag.BoolVar(&testOptions.enableCoverage, "coverage", false, "Run tests and measure coverage")
	flag.BoolVar(&testOptions.enableAntreaIPAM, "antrea-ipam", false, "Run tests with AntreaIPAM")
	flag.BoolVar(&testOptions.flowVisibility, "flow-visibility", false, "Run flow visibility tests")
	flag.BoolVar(&testOptions.deployAntrea, "deploy-antrea", true, "Deploy Antrea before running tests")
	flag.StringVar(&testOptions.coverageDir, "coverage-dir", "", "Directory for coverage data files")
	flag.StringVar(&testOptions.skipCases, "skip-cases", "", "Key words to skip cases")
	flag.StringVar(&testOptions.linuxVMs, "linuxVMs", "", "hostname of Linux VMs")
	flag.StringVar(&testOptions.windowsVMs, "windowsVMs", "", "hostname of Windows VMs")
	flag.StringVar(&testOptions.externalServerIPs, "external-server-ips", "", "IP addresses of external server, at most one IP per IP family")
	flag.StringVar(&testOptions.vlanSubnets, "vlan-subnets", "", "IP subnets of the VLAN network the Nodes reside in, at most one subnet per IP family")
	flag.IntVar(&testOptions.vlanID, "vlan-id", 0, "ID of the VLAN network the Nodes reside in")
	flag.Parse()

	cleanupLogging := testOptions.setupLogging()
	defer cleanupLogging()

	testData = &TestData{}
	if err := testData.InitProvider(testOptions.providerName, testOptions.providerConfigPath); err != nil {
		log.Fatalf("Error when initializing provider: %v", err)
	}
	log.Println("Creating K8s ClientSet")
	kubeconfigPath, err := testData.provider.GetKubeconfigPath()
	if err != nil {
		log.Fatalf("Error when getting Kubeconfig path: %v", err)
	}
	if err := testData.CreateClient(kubeconfigPath); err != nil {
		log.Fatalf("Error when creating K8s ClientSet: %v", err)
	}
	log.Println("Collecting information about K8s cluster")
	if err := testData.collectClusterInfo(); err != nil {
		log.Fatalf("Error when collecting information about K8s cluster: %v", err)
	}
	if clusterInfo.podV4NetworkCIDR != "" {
		log.Printf("Pod IPv4 network: '%s'", clusterInfo.podV4NetworkCIDR)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		log.Printf("Pod IPv6 network: '%s'", clusterInfo.podV6NetworkCIDR)
	}
	if clusterInfo.svcV4NetworkCIDR != "" {
		log.Printf("Service IPv4 network: '%s'", clusterInfo.svcV4NetworkCIDR)
	}
	if clusterInfo.svcV6NetworkCIDR != "" {
		log.Printf("Service IPv6 network: '%s'", clusterInfo.svcV6NetworkCIDR)
	}
	log.Printf("Num nodes: %d", clusterInfo.numNodes)
	if err := testData.collectExternalInfo(); err != nil {
		log.Fatalf("Error when collecting external information: %v", err)
	}
	err = ensureAntreaRunning(testData)
	if err != nil {
		log.Fatalf("Error when deploying Antrea: %v", err)
	}
	// Collect PodCIDRs after Antrea is running as Antrea is responsible for allocating PodCIDRs in some cases.
	// Polling is not needed here because antrea-agents won't be up and running if PodCIDRs of their Nodes are not set.
	if err = testData.collectPodCIDRs(); err != nil {
		log.Fatalf("Error collecting PodCIDRs: %v", err)
	}
	AntreaConfigMap, err = testData.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		log.Fatalf("Error when getting antrea-config configmap: %v", err)
	}
	if testOptions.enableCoverage {
		cleanupCoverage := testOptions.setupCoverage(testData)
		defer cleanupCoverage()
		defer gracefulExitAntrea(testData)
	}
	ret := m.Run()
	return ret
}

func gracefulExitAntrea(testData *TestData) {
	if err := testData.gracefulExitAntreaController(testOptions.coverageDir); err != nil {
		log.Fatalf("Error when gracefully exit antrea controller: %v", err)
	}
	if err := testData.gracefulExitAntreaAgent(testOptions.coverageDir, "all"); err != nil {
		log.Fatalf("Error when gracefully exit antrea agent: %v", err)
	}
	if err := testData.collectAntctlCovFilesFromControlPlaneNode(testOptions.coverageDir); err != nil {
		log.Fatalf("Error when collecting antctl coverage files from control-plane Node: %v", err)
	}
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}
