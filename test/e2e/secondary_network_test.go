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
	logs "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Structures defined for generating Pod yaml files
type PodSpec struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}
type Annotations struct {
	K8SV1CniCncfIoNetworks string `yaml:"k8s.v1.cni.cncf.io/networks"`
}
type Labels struct {
	App string `yaml:"app"`
}
type Metadata struct {
	Annotations Annotations `yaml:"annotations"`
	Labels      Labels      `yaml:"labels"`
	Name        string      `yaml:"name"`
}
type Requests struct {
	IntelComIntelSriovNetdevice string `yaml:"intel.com/intel_sriov_netdevice"`
}
type Limits struct {
	IntelComIntelSriovNetdevice string `yaml:"intel.com/intel_sriov_netdevice"`
}
type Resources struct {
	Requests Requests `yaml:"requests"`
	Limits   Limits   `yaml:"limits"`
}

type Containers struct {
	Image           string    `yaml:"image"`
	ImagePullPolicy string    `yaml:"imagePullPolicy"`
	Command         []string  `yaml:"command"`
	Args            []string  `yaml:"args"`
	Name            string    `yaml:"name"`
	Resources       Resources `yaml:"resources"`
}

type Spec struct {
	Containers    [1]Containers `yaml:"containers"`
	RestartPolicy string        `yaml:"restartPolicy"`
}

// SRIOV interface information parsed from secondary_network_config_param.yaml file.
type secondary_network_config struct {
	InterfaceType                string
	NetworkInterface             string
	NumberOfVFs                  string
	TotalNumberOfVirtualNetworks int
	VirtualNetworkNames          []string
	NumberOfPods                 int
	Describe                     [][]string
	PodSpec                      []string
	UserName                     string
	NodeIp                       string
	NodePath                     string
	Passwd                       string
}

var networkInterfaceName string
var totalNumberOfVirtualFunctions string
var totalVirtualNetworks int
var nameOfVirtualNetwork []string
var totalNumberOfPods int
var nameOfPods [20]string
var listOfVirtualNetworksPerPod [20]int
var nameOfVirtualNetworkPerPod [20][]string
var nameOfInterfacePerPod [20][]string
var nameOfYamlPerPod [20]string
var controlNodeUsername string
var controlNodeIP string
var controlNodePath string
var controlNodePasswd string

var (
	// configuration files to be downloaded for sencondary network test needs.
	secondaryNetworkConfigUrls = [...]string{
		"https://raw.githubusercontent.com/k8snetworkplumbingwg/sriov-network-device-plugin/master/deployments/k8s-v1.16/sriovdp-daemonset.yaml",
		"https://raw.githubusercontent.com/k8snetworkplumbingwg/sriov-network-device-plugin/master/deployments/configMap.yaml",
		"https://raw.githubusercontent.com/k8snetworkplumbingwg/whereabouts/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml",
	}
)

const secondary_network_config_path = "/secondary_network/"
const LogFileName = "." + secondary_network_config_path + "sanity.log"
const configMap = "configMap.yaml"
const sriovDaemonset = "sriovdp-daemonset.yaml"
const antrea = "antrea-secondary-network-e2e.yml"
const whereabouts = "whereabouts.cni.cncf.io_ippools.yaml"
const netAttachDef = "network-attachment-definition-crd.yaml"
const configfile = "secondary_network_configuration.yaml"

// apply the sriov-network device plugin configMap and deamonSet to the system.
func (data *TestData) deploySriovDevicePluginAtNode() error {
	var err error
	var respCode int
	var pathOfSriovConfigMap, pathOfSriovDaemonSet string
	pathOfSriovConfigMap = "." + secondary_network_config_path + configMap
	respCode, _, _, err = data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s -n kube-system", pathOfSriovConfigMap))

	fmt.Printf("kubectl apply -f %s -n kube-system", pathOfSriovConfigMap)
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deploying sriov-network-device-plugin ConfigMap at remote cluster - rc: %v, err: %v", respCode, err)
	}

	pathOfSriovDaemonSet = "." + secondary_network_config_path + sriovDaemonset
	respCode, _, _, err = data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s", pathOfSriovDaemonSet))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deploying sriov-network-device-plugin DaemonSet at remote cluster - rc: %v, err: %v", respCode, err)
	}
	return nil
}

func (data *TestData) deleteSriovDevicePluginAtNode() error {
	var pathOfSriovConfigMap, pathOfSriovDaemonSet string
	pathOfSriovConfigMap = "." + secondary_network_config_path + configMap
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s", pathOfSriovConfigMap))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deleting sriov-network-device-plugin ConfigMap at remote cluster - rc: %v, err: %v", respCode, err)
	}

	pathOfSriovDaemonSet = "." + secondary_network_config_path + sriovDaemonset
	respCode, _, _, err = data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s", pathOfSriovDaemonSet))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deleting sriov-network-device-plugin DaemonSet at remote cluster - rc: %v, err: %v", respCode, err)
	}
	return nil
}

// configures SRIOV with the number of virtual functions specified in the secondary_network_params.yaml file.
func (data *TestData) configureSriovVFsAtNode(networkInterfaceName, numberOfVirtualFunctions string) error {
	var err error
	sysCmd := "sudo bash -c echo '" + numberOfVirtualFunctions + "' > /sys/class/net/" + networkInterfaceName + "/device/sriov_numvfs"
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), sysCmd)
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when Configuring the Virtual Functions at remote sriov node.\n")
	}
	return nil
}

// Deploy Network Attachment Definition CRD on the control node of a cluster.
func (data *TestData) deployNetworkAttachmentDefinition() error {
	pathNetAttachDefinition := "." + secondary_network_config_path + netAttachDef
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s -n kube-system", pathNetAttachDefinition))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deploying network-attachment-definition at remote cluster - rc: %v, err: %v", respCode, err)
	}
	return nil
}

// Copy all the secondary network related prerequisite configuration files to the control node of the cluster.
// TODO (WIP): Change this implementation to push the files from Antrea test execution node to the cluster. Current implementation pull the files.
//             This is required to avoid sharing the test execution account details with the remote node.
func (data *TestData) copyFilesToControlPlaneNodeName() error {
	respCode1, _, _, err1 := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("mkdir -P .%s", secondary_network_config_path))
	if err1 != nil || respCode1 != 0 {
		return fmt.Errorf("Error creating secondary_network directory failed at remote node - rc: %v, err: %v", respCode1, err1)
	}
	// Parse the config file to get the control node info
	//var err error
	secondaryNetworkParam := make(map[string]secondary_network_config)
	// 1. Parse secondary network test configuration file and get config information.
	secondaryNetworkConfigYaml, _ := ioutil.ReadFile("." + secondary_network_config_path + configfile)
	err2 := yaml.Unmarshal(secondaryNetworkConfigYaml, &secondaryNetworkParam)
	if err2 != nil {
		return fmt.Errorf("Parsing %s failed.", configfile)
	}

	control_node_conf := secondaryNetworkParam["controlnode_info"]
	controlNodeUsername = control_node_conf.UserName
	controlNodeIP = control_node_conf.NodeIp
	controlNodePath = control_node_conf.NodePath
	controlNodePasswd = control_node_conf.Passwd

	Path := controlNodeUsername + "@" + controlNodeIP + ":" + controlNodePath + secondary_network_config_path + "*.*"
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("sshpass -p %s scp -o StrictHostKeyChecking=no %s ./secondary_network", controlNodePasswd, Path))

	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when trying to copy config files at remote cluster - rc: %v, err: %v", respCode, err)
	}

	return nil

}

// Remove/Cleanup Network Attachment Definitation CRD from the cluster.
func (data *TestData) deleteNetworkAttachmentDefinition() error {
	pathNetAttachDefinition := "." + secondary_network_config_path + netAttachDef
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s -n kube-system", pathNetAttachDefinition))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deleting network-attachment-definition at remote cluster - rc: %v, err: %v", respCode, err)
	}
	return nil
}

// Deploy virtual network definition as per the secondary network configuration needs.
func (data *TestData) deployVirtualNetworks(nameOfVirtualNetwork []string) error {
	for _, virtualNetworkName := range nameOfVirtualNetwork {
		pathOfVirtualNetwork := "." + secondary_network_config_path + virtualNetworkName
		respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s -n kube-system", pathOfVirtualNetwork))
		if err != nil || respCode != 0 {
			return fmt.Errorf("Error when deploying %s remote cluster - rc: %v, err: %v", pathOfVirtualNetwork, respCode, err)
		}
	}
	return nil
}

// Remove/Cleanup virtual network definition from the cluster.
func (data *TestData) deleteVirtualNetworks(nameOfVirtualNetwork []string) error {
	for _, virtualNetworkName := range nameOfVirtualNetwork {
		pathOfVirtualNetwork := "." + secondary_network_config_path + virtualNetworkName
		respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s -n kube-system", pathOfVirtualNetwork))
		if err != nil || respCode != 0 {
			return fmt.Errorf("Error when deleting %s remote cluster - rc: %v, err: %v", pathOfVirtualNetwork, respCode, err)
		}
	}
	return nil
}

// Deploy Whereabouts CNI for secondary network's global IPAM.
func (data *TestData) deployWhereaboutsCNI() error {
	pathOfWhereabouts := "." + secondary_network_config_path + antrea
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s -n kube-system", pathOfWhereabouts))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deploying %s remote cluster - rc: %v, err: %v", pathOfWhereabouts, respCode, err)
	}
	return nil
}

// Remove/Cleanup Whereabouts CNI configuration.
func (data *TestData) deleteWhereaboutsCNI() error {
	pathOfWhereabouts := "." + secondary_network_config_path + whereabouts
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s -n kube-system", pathOfWhereabouts))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deleting %s remote cluster - rc: %v, err: %v", pathOfWhereabouts, respCode, err)
	}
	return nil
}

// Remove/Cleanup secondary network enabled Antrea CNI on the test execution cluster.
func (data *TestData) deleteAntreaCNI() error {
	pathOfAntreaCNI := "." + secondary_network_config_path + antrea
	respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s -n kube-system", pathOfAntreaCNI))
	if err != nil || respCode != 0 {
		return fmt.Errorf("Error when deleting %s remote cluster - rc: %v, err: %v", pathOfAntreaCNI, respCode, err)
	}
	return nil
}

// Toggle IP link state of the provided Network interface
func (data *TestData) toggleIPLinkAtNode(networkInterfaceName string, state int) error {
	if state == 0 {
		respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("ip link set %s down", networkInterfaceName))
		if err != nil || respCode != 0 {
			return fmt.Errorf("Toggle network interface '%s' state to UP at remote node failed!.", networkInterfaceName)
		}
	} else {
		respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("ip link set %s up", networkInterfaceName))
		if err != nil || respCode != 0 {
			return fmt.Errorf("Toggle network interface '%s' state to DOWN at remote node failed!.", networkInterfaceName)
		}
	}
	return nil
}

// Create Pod annotation string, used in the generation of each Pod yaml file.
func formAnnotationStringOfPod(pod int) string {
	var annotation_str = ""
	for _, xPodVN := range listOfVirtualNetworksPerPod {
		var Input = "{\"name\": \"" + nameOfVirtualNetworkPerPod[pod][xPodVN] + "\" ,\"interface\": \"" + nameOfInterfacePerPod[pod][xPodVN] + "\" , \"type\": \"sriov\"}"
		if annotation_str == "" {
			annotation_str = "[" + Input
		} else {
			annotation_str = annotation_str + "," + Input
		}
	}
	annotation_str = annotation_str + "]"
	return annotation_str
}

func generatePodSpecWithSecondaryNetworkAnnotation() error {
	// Generating yaml files for all the Pods
	for xPod := 0; xPod < totalNumberOfPods; xPod++ {
		annotationString := formAnnotationStringOfPod(xPod)
		// Formation of Pod Spec, Metadata, kind and versionme
		podSpecObj := PodSpec{APIVersion: "v1",
			Kind:     "Pod",
			Metadata: Metadata{Annotations: Annotations{K8SV1CniCncfIoNetworks: annotationString}, Labels: Labels{App: "testsecpod"}, Name: nameOfPods[xPod]},
			Spec: Spec{Containers: [1]Containers{{Image: "busybox", ImagePullPolicy: "IfNotPresent", Command: []string{"sleep"}, Args: []string{"infinity"}, Name: "busyboxpod",
				Resources: Resources{Requests: Requests{IntelComIntelSriovNetdevice: "3"}, Limits: Limits{IntelComIntelSriovNetdevice: "3"}}}}, RestartPolicy: "OnFailure"}}

		data, err := yaml.Marshal(&podSpecObj)
		if err != nil {
			log.Fatal(err)
		}
		// Writing into the Pod yaml file
		error2 := ioutil.WriteFile(nameOfYamlPerPod[xPod], data, 0)
		if error2 != nil {
			fmt.Errorf("Error in writing to yaml file! Please Check.\n")
			log.Fatal(error2)
		}
	}
	return nil
}

func (data *TestData) createSecondaryNetworkPods() error {
	for _, YamlName := range nameOfYamlPerPod {
		respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s -n kube-system", YamlName))
		if err != nil || respCode != 0 {
			return fmt.Errorf("Error when creating %s secondary test Pods - rc: %v, err: %v", YamlName, respCode, err)
		}
	}
	return nil
}

func (data *TestData) deleteSecondaryNetworkPods() error {
	for _, podName := range nameOfPods {
		respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete Pod -f %s -n kube-system", podName))
		if err != nil || respCode != 0 {
			return fmt.Errorf("Error when deleting %s secondary test Pods - rc: %v, err: %v", podName, respCode, err)
		}
	}
	return nil
}

func (data *TestData) checkSecondaryInterfaces() error {
	for _, PodName := range nameOfPods {
		respCode, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl exec -it %s -n kube-system -- ip addr show", PodName))
		if err != nil || respCode != 0 {
			return fmt.Errorf("Error when creating interfaces on %s remote cluster - rc: %v, err: %v", PodName, respCode, err)
		}
	}
	return nil
}

func (data *TestData) generateAntreaConfig() error {
	var err error
	genManifest := "./../../hack/generate-manifest.sh"
	_, err = os.Stat(genManifest)
	if err != nil {
		return err
	}
	genManifest = genManifest + " --sriov --whereabouts > ." + secondary_network_config_path + "antrea-secondary-network-e2e.yml"
	cmd := exec.Command("sudo", "bash", "-c", genManifest)

	if err = cmd.Start(); err != nil {
		return fmt.Errorf("Failed to generate Antrea.yml : %v", err)
	}
	return nil
}

func (data *TestData) downloadFileFromUrl(urlString string) error {
	var wg sync.WaitGroup
	logs.Infof("EXTERNAL URL: %v", urlString)
	wg.Add(1)
	go func() {
		defer wg.Done()
		Path := "." + secondary_network_config_path
		logs.Infof("EXTERNAL PATH: %v", Path)
		getYamlHandle := exec.Command("wget", "-P", Path, urlString)
		getYamlHandle.Run()
	}()
	wg.Wait()
	return nil
}

func (data *TestData) downloadSecondaryNetworkPrerequisiteYamlFiles() error {
	for _, urlString := range secondaryNetworkConfigUrls {
		logs.Infof("EXTERNAL URL: %v", urlString)
		data.downloadFileFromUrl(urlString)
	}
	return nil
}

// Deploy all the secondary network specific configurations at the test execution cluster prior to the tests.
func (data *TestData) deploySecondaryNetworkPrerequisiteConfig() error {
	var err error
	secondaryNetworkParam := make(map[string]secondary_network_config)
	// 1. Parse secondary network test configuration file and get config information.
	secondaryNetworkConfigYaml, _ := ioutil.ReadFile("." + secondary_network_config_path + configfile)
	err = yaml.Unmarshal(secondaryNetworkConfigYaml, &secondaryNetworkParam)
	if err != nil {
		return fmt.Errorf("Parsing %s failed.", configfile)
	}
	interface_type := secondaryNetworkParam["interface_type"]
	sriov_config_info := secondaryNetworkParam["sriov_conf"]
	//control_node_conf := secondaryNetworkParam["controlnode_info"]
	virtual_network_info := secondaryNetworkParam["vir_net"]
	// This Pod info is used wherever required
	test_pod_info := secondaryNetworkParam["create_pod"]
	totalNumberOfPods = test_pod_info.NumberOfPods

	for nPod := 0; nPod < totalNumberOfPods; nPod++ {
		nameOfPods[nPod] = test_pod_info.Describe[nPod][0]
		convertStrToInt, _ := strconv.Atoi(test_pod_info.Describe[nPod][1])
		listOfVirtualNetworksPerPod[nPod] = convertStrToInt
		nameOfVirtualNetworkPerPod[nPod] = strings.Split(test_pod_info.Describe[nPod][2], ",")
		nameOfInterfacePerPod[nPod] = strings.Split(test_pod_info.Describe[nPod][3], ",")
		nameOfYamlPerPod[nPod] = test_pod_info.Describe[nPod][4]
	}
	// Secondary Network Interface name.
	baseNetworkInterfaceName := sriov_config_info.NetworkInterface
	// Number of VFs to be configured on the host.
	totalNumberOfVirtualFunctions = sriov_config_info.NumberOfVFs
	// If the number of VF info doesn't exists in the secondary network test config file (for SRIOV-VF), stop test execution.
	convertStrToIntVFs, _ := strconv.Atoi(totalNumberOfVirtualFunctions)
	if convertStrToIntVFs == 0 {
		return fmt.Errorf("VF count not provided at the Secondarynetworkparams.yaml. Test execution failed.")
	}
	// If base network interface name doesn't exists in the secondary network test config (for SRIOV-VF), stop test execution.
	if baseNetworkInterfaceName == "" {
		return fmt.Errorf("Base Network interface is not provided at the Secondarynetworkparams.yaml. Test execution failed.")
	}
	// SRIOV VF configuration and sriov device plugin deployment is required only if the interface
	if interface_type.InterfaceType == "sriov" {
		// 2. Configure virtual functions on the Intel SRIOV NIC.
		// Delete all existing VFs(if any) on the base interface provided.
		data.configureSriovVFsAtNode(baseNetworkInterfaceName, "0")
		// Put the base interface state to down.
		//data.toggleIPLinkAtNode(baseNetworkInterfaceName, 0)
		// Create totalNumberOfVirtualFunctions on top of the base interface provided.
		if err = data.configureSriovVFsAtNode(baseNetworkInterfaceName, totalNumberOfVirtualFunctions); err != nil {
			fmt.Println(err)
			return fmt.Errorf("Error in configureSriovVFsAtNode. Test execution failed.")
		}
		// Put the base interface state to Up.
		data.toggleIPLinkAtNode(baseNetworkInterfaceName, 1)
		// 3. Deploy SRIOV device plugin.
		if err = data.deploySriovDevicePluginAtNode(); err != nil {
			return err
		}
	}
	// 4. Deploy network attachment definition CRD.
	if err = data.deployNetworkAttachmentDefinition(); err != nil {
		return err
	}
	// Control node information for copying config files
	//controlNodeUsername = control_node_conf.UserName
	//controlNodeIP = control_node_conf.NodeIp
	//controlNodePath = control_node_conf.NodePath
	// 5.a Parse virtual network names.
	var virtualNetworkNames []string
	if virtual_network_info.VirtualNetworkNames != nil {
		for _, netName := range virtual_network_info.VirtualNetworkNames {
			netName = strings.TrimSpace(netName)
			virtualNetworkNames = append(virtualNetworkNames, netName)
		}
		// 5.b Deploy virutal networks
		if err = data.deployVirtualNetworks(virtualNetworkNames); err != nil {
			return err
		}
	}
	// 6. Configure whereabouts CNI for secondary network global IPAM needs
	if err = data.deployWhereaboutsCNI(); err != nil {
		return err
	}
	return nil
}

func (data *TestData) deployAntreaWithSecondaryNetworkConfig() error {
	pathOfAntreaConfig := "." + secondary_network_config_path + antrea
	rc, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s", pathOfAntreaConfig))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying Antrea; is %s available on the %s Node?", pathOfAntreaConfig, controlPlaneNodeName())
	}
	rc, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status deploy/%s --timeout=%v", antreaNamespace, antreaDeployment, defaultTimeout))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when waiting for antrea-controller rollout to complete - rc: %v - stdout: %v - stderr: %v - err: %v", rc, stdout, stderr, err)
	}
	rc, stdout, stderr, err = data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status ds/%s --timeout=%v", antreaNamespace, antreaDaemonSet, defaultTimeout))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when waiting for antrea-agent rollout to complete - rc: %v - stdout: %v - stderr: %v - err: %v", rc, stdout, stderr, err)
	}
	return nil
}

func (data *TestData) generateSecondaryNetworkTestPods() error {
	err := generatePodSpecWithSecondaryNetworkAnnotation()
	if err != nil {
		fmt.Errorf("Error in deploying antrea with secondary network config!")
	}

	err2 := data.createSecondaryNetworkPods()
	if err2 != nil {
		fmt.Errorf("Error in deploying antrea with secondary network config!")
	}

	return nil
}

func TestNativeSecondaryNetwork(t *testing.T) {
	skipIfHasWindowsNodes(t)
	//	skipIfSecondaryNetworkDisabled(t)
	// once the setupTestWithSecondaryNetworkConfig is successful, we have all the prerequisites enabled and running.
	data, err := setupTestWithSecondaryNetworkConfig(t)
	if err != nil {
		t.Fatalf("Error when up setupTestWithSecondaryNetworkConfig: %v", err)
	}
	defer teardownSecondaryNetworkTest(t, data)
	t.Run("testDeployAntreaWithSecondaryNetworkConfig", func(t *testing.T) {
		data.deployAntreaWithSecondaryNetworkConfig()
	})
	t.Run("testGenerateSecondaryNetworkTestPods", func(t *testing.T) {
		data.generateSecondaryNetworkTestPods()
	})
}
