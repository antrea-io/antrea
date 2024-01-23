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

package e2e

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	logs "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	antreae2e "antrea.io/antrea/test/e2e"
)

// Structure to extract and store the secondary network configuration information parsed from secondary-network-configuration.yml.
type PodConfig struct {
	InterfaceType struct {
		interfaceType string `yaml:"interfacetype"`
	} `yaml:"interface_type"`
	SriovConf struct {
		networkInterface string `yaml:"networkinterface"`
		numberOfVfs      int    `yaml:"numberofvfs"`
	} `yaml:"sriov_conf"`
	VirNet struct {
		totalNumberOfVirtualNetworks int      `yaml:"totalnumberofvirtualnetworks"`
		virtualNetworknames          []string `yaml:"virtualnetworknames"`
	} `yaml:"vir_net"`
	CreatePod struct {
		numberOfPods int             `yaml:"numberofpods"`
		describe     [][]interface{} `yaml:"describe"`
	} `yaml:"create_pod"`
}

var service PodConfig

// Structure for extracting the variables for describing the Pod from secondary-network-configuration.yml file.
type describePodInfo struct {
	nameOfPods                   string
	countOfVirtualNetworksPerPod int
	nameOfVirtualNetworkPerPod   []string
	nameOfInterfacePerPod        []string
}

var podData []describePodInfo
var totalNumberOfPods int
var interfaceType string

const (
	secondaryNetworkConfigYAML = "./infra/secondary-network-configuration.yml"
	nameSpace                  = "kube-system"
	ctrName                    = "busyboxpod"
	testPodName                = "testsecpod"
	osType                     = "linux"
	count                      = 5
	size                       = 40
	defaultTimeout             = 10 * time.Second
	reqName                    = "intel.com/intel_sriov_netdevice"
	resNum                     = 3
)
const (
	podName = iota
	podVNsCount
	podVirtualNetwork
	podInterfaceName
)

// setupTestWithSecondaryNetworkConfig sets up all the prerequisites for running the test including the antrea enabled and running, extracting Pod and secondary network interface information and setting log directory for the test
func (data *TestData) setupTestWithSecondaryNetworkConfig(tb testing.TB) (*TestData, error) {
	// Extracting the Pods information from the secondary_network_configuration.yml file.
	if err := data.extractPodsInfo(); err != nil {
		tb.Errorf("Error in extracting Pods info from secondary-network-configuration.yml : %v", err)
		return nil, err
	}
	// Set log directory for test execution.
	if err := data.e2eTestData.SetupLogDirectoryForTest(tb.Name()); err != nil {
		tb.Errorf("Error creating logs directory '%s': %v", data.logsDirForTestCase, err)
		return nil, err
	}
	return data, nil
}

// extractPodsInfo extracts the Pod and secondary network interface information for the creation of Podsfrom secondary-network-configuration.yaml file
func (data *TestData) extractPodsInfo() error {
	var errYamlUnmarshal error
	_, err := os.Stat(secondaryNetworkConfigYAML)
	if err != nil {
		return fmt.Errorf("Parsing of the Pod configuration file failed")

	}
	secondaryNetworkConfigYAML, _ := os.ReadFile(secondaryNetworkConfigYAML)
	errYamlUnmarshal = yaml.Unmarshal(secondaryNetworkConfigYAML, &service)
	if errYamlUnmarshal != nil {
		return fmt.Errorf("Parsing %s failed", secondaryNetworkConfigYAML)
	}
	interfaceType = service.InterfaceType.interfaceType
	totalNumberOfPods = service.CreatePod.numberOfPods
	for _, s := range service.CreatePod.describe {
		output := describePodInfo{nameOfPods: s[podName].(string), countOfVirtualNetworksPerPod: s[podVNsCount].(int), nameOfVirtualNetworkPerPod: strings.Split(s[podVirtualNetwork].(string), ","), nameOfInterfacePerPod: strings.Split(s[podInterfaceName].(string), ",")}
		podData = append(podData, output)
	}
	return nil
}

// formAnnotationStringOfPod forms the annotation string, used in the generation of each Pod YAML file.
func (data *TestData) formAnnotationStringOfPod(pod int) string {
	var annotationString = ""
	for xPodVN := 0; xPodVN < podData[pod].countOfVirtualNetworksPerPod; xPodVN++ {
		var podNetworkSpec = "{\"name\": \"" + podData[pod].nameOfVirtualNetworkPerPod[xPodVN] + "\" ,\"interface\": \"" + podData[pod].nameOfInterfacePerPod[xPodVN] + "\" , \"type\": \"" + interfaceType + "\"}"
		if annotationString == "" {
			annotationString = "[" + podNetworkSpec
		} else {
			annotationString = annotationString + "," + podNetworkSpec
		}
	}
	annotationString = annotationString + "]"
	return annotationString
}

// createPodOnNode creates the Pod for the specific annotations as per the parsed Pod information using the NewPodBuilder API
func (data *TestData) createPodOnNode(t *testing.T, ns string, nodeName string) error {
	var err error
	for xPod := 0; xPod < totalNumberOfPods; xPod++ {
		err := data.createPodForSecondaryNetwork(ns, nodeName, xPod, testPodName, resNum)
		if err != nil {
			return fmt.Errorf("Error in creating pods.., err: %v", err)
		}
	}
	return err
}

// getSecondaryInterface shows up the secondary interfaces created for the specific Pod and extracts the IP address for the same.
func (data *TestData) getSecondaryInterface(targetPod int, targetInterface int) (string, error) {
	cmd := []string{"/bin/sh", "-c", fmt.Sprintf("ip addr show %s | grep \"inet\" | awk '{print $2}' | cut -d/ -f1", podData[targetPod].nameOfInterfacePerPod[targetInterface])}
	stdout, _, err := data.e2eTestData.RunCommandFromPod(nameSpace, podData[targetPod].nameOfPods, ctrName, cmd)
	stdout = strings.TrimSuffix(stdout, "\n")
	if stdout == "" {
		log.Fatalf("Error: Interface %s not found on %s. err: %v", podData[targetPod].nameOfInterfacePerPod[targetInterface], podData[targetPod].nameOfPods, err)
	}
	return stdout, nil
}

// checkSubnet checks if the IP address to be pinged has the same subnet as the Pod from which the IP Address is pinged.
func (data *TestData) checkSubnet(t *testing.T, sourcePod int, targetPod int, targetInterface int) (bool, error) {
	for podCheckForSubnet := 0; podCheckForSubnet < podData[sourcePod].countOfVirtualNetworksPerPod; podCheckForSubnet++ {
		if podData[sourcePod].nameOfVirtualNetworkPerPod[podCheckForSubnet] == podData[targetPod].nameOfVirtualNetworkPerPod[targetInterface] {
			_, err := data.getSecondaryInterface(sourcePod, podCheckForSubnet)
			if err != nil {
				t.Logf("Error in ping: Interface %s for the source test Pod %s not created", podData[sourcePod].nameOfInterfacePerPod[podCheckForSubnet], podData[sourcePod].nameOfPods)
				return false, err
			}
		}
	}
	return true, nil
}

// pingBetweenInterfaces parses through all the created Podsand pings the other Pod if the IP Address of the secondary network interface of the Pod is in the same subnet. Sleep time of 3 seconds is ensured for the successful ping between the pods.
func (data *TestData) pingBetweenInterfaces(t *testing.T) error {
	for sourcePod := 0; sourcePod < totalNumberOfPods; sourcePod++ {
		for targetPod := 0; targetPod < totalNumberOfPods; targetPod++ {
			for targetInterface := 0; targetInterface < podData[targetPod].countOfVirtualNetworksPerPod; targetInterface++ {
				if podData[targetPod].nameOfPods == podData[sourcePod].nameOfPods {
					continue
				}
				_, err := data.e2eTestData.PodWaitFor(defaultTimeout, podData[targetPod].nameOfPods, nameSpace, func(pod *corev1.Pod) (bool, error) {
					return pod.Status.Phase == corev1.PodRunning, nil
				})
				if err != nil {
					t.Logf("Error when waiting for the perftest client Pod: %s", podData[targetPod].nameOfPods)
				}

				flag, _ := data.checkSubnet(t, sourcePod, targetPod, targetInterface)
				if flag != false {
					secondaryIpAddress, _ := data.getSecondaryInterface(targetPod, targetInterface)
					ip := net.ParseIP(secondaryIpAddress)
					if ip != nil {
						var IPToPing antreae2e.PodIPs
						if ip.To4() != nil {
							IPToPing = antreae2e.PodIPs{IPv4: &ip}
						} else {
							IPToPing = antreae2e.PodIPs{IPv6: &ip}
						}
						err := data.e2eTestData.RunPingCommandFromTestPod(antreae2e.PodInfo{Name: podData[sourcePod].nameOfPods, OS: osType, NodeName: clusterInfo.controlPlaneNodeName, Namespace: nameSpace}, nameSpace, &IPToPing, ctrName, count, size, false)
						if err == nil {
							logs.Infof("Ping '%s' -> '%s'( Interface: %s, IP Address: %s): OK", podData[sourcePod].nameOfPods, podData[targetPod].nameOfPods, podData[targetPod].nameOfInterfacePerPod[targetInterface], secondaryIpAddress)
						} else {
							t.Logf("Ping '%s' -> '%s'( Interface: %s, IP Address: %s): ERROR (%v)", podData[sourcePod].nameOfPods, podData[targetPod].nameOfPods, podData[targetPod].nameOfInterfacePerPod[targetInterface], secondaryIpAddress, err)
						}
					} else {
						t.Logf("Error in Ping: Target interface %v of %v Pod not created", podData[targetPod].nameOfInterfacePerPod[targetInterface], podData[targetPod].nameOfPods)
					}
				}
			}
		}
	}
	return nil
}

// The Wrapper function createPodForSecondaryNetwork creates the Pod adding the annotation, arguments, commands, Node, container name,
// resource requests and limits as arguments with the NewPodBuilder API
func (data *TestData) createPodForSecondaryNetwork(ns string, nodeName string, podNum int, testPodName string, resNum int64) error {
	computeResources := resource.NewQuantity(resNum, resource.DecimalSI)
	return antreae2e.NewPodBuilder(podData[podNum].nameOfPods, ns, busyboxImage).OnNode(nodeName).WithContainerName(ctrName).WithCommand([]string{"sleep", "infinity"}).WithAnnotations(
		map[string]string{
			"k8s.v1.cni.cncf.io/networks": fmt.Sprintf("%s", data.formAnnotationStringOfPod(podNum)),
		}).WithLabels(
		map[string]string{
			"App": fmt.Sprintf("%s", testPodName),
		}).WithResources(corev1.ResourceList{reqName: *computeResources}, corev1.ResourceList{reqName: *computeResources}).Create(data.e2eTestData)
}

func TestNativeSecondaryNetwork(t *testing.T) {
	// once the setupTestWithSecondaryNetworkConfig is successful, we have all the prerequisites enabled and running.
	_, err := testData.setupTestWithSecondaryNetworkConfig(t)
	if err != nil {
		t.Logf("Error when setupTestWithSecondaryNetworkConfig: %v", err)
	}
	t.Run("testCreateTestPodOnNode", func(t *testing.T) {
		testData.createPodOnNode(t, nameSpace, clusterInfo.controlPlaneNodeName)
	})
	t.Run("testpingBetweenInterfaces", func(t *testing.T) {
		err := testData.pingBetweenInterfaces(t)
		if err != nil {
			t.Logf("Error when pinging between interfaces: %v", err)
		}
	})
}
