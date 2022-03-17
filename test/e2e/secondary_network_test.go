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

package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Structures defined for generating pod yaml files
type PodYamlFile struct {
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
	NetworkInterface              string
	NumberOfVFs                   string
	TotalNumberOfVirtualNetworks  int
	VirtualNetworkNames           []string
	NumberOfPods                  int
	PodNames                      []string
	NumberOfVirtualNetworksPerPod []int
	PodVirtualNetworkNames        [][]string
	PodInterfaceNames             [][]string
	PodYamlFiles                  []string
}

var networkInterfaceName string
var totalNumberOfVirtualFunctions string
var totalVirtualNetworks int
var nameOfVirtualNetwork [20]string
var totalNumberOfPods int
var nameOfPods [20]string
var listOfVirtualNetworksPerPod [20]int
var nameOfVirtualNetworkPerPod [20][20]string
var nameOfInterfacePerPod [20][20]string
var nameOfYamlPerPod [20]string

//configuration files to be accessed for the secondary network test
var configFile = []string{
	"secondary_network_configuration.yaml",
	"network-attachment-definition-crd.yaml",
	"whereabouts.cni.cncf.io_ippools.yaml",
	"antrea-secondary-network-e2e.yml",
	"sriov-network-device-plugin/deployments/configMap.yaml",
	"sriov-network-device-plugin/deployments/k8s-v1.16/sriovdp-daemonset.yaml",
}

const secondary_network_config_path = "./secondary_network/"
const LogFileName = secondary_network_config_path + "sanity.log"

// This function parses through all the dependant file names and ensure it presence under
// <working dir>/test/e2e/secondary_network directory
func startSanity(intVariable int) int {
	for i := 0; i < len(configFile); i++ {
		_, errorStatus := os.Stat(secondary_network_config_path + configFile[i])
		if errorStatus != nil {
			fmt.Errorf("Secondary network Test configuration file (%s) Not found!\n", configFile[i])
			log.Fatal(errorStatus)
		}
	}

	// Checking if sanity log file is present
	_, errorLogFile := os.Stat(LogFileName)
	if errorLogFile == nil {
		exec.Command("rm", LogFileName).Output()
	}
	return intVariable
}

// This function checks if the correct interface name is provided from the yaml file or not. If not, It loops thru all the available interfaces and
// figure out the base interface in which SRIOV VFs can be enabled
func checkNetworkInterface(networkInterfaceNameFromYaml string) string {
	var networkInterface string
	allInterface, errorListingInterface := exec.Command("ls", "-1", "/sys/class/net").Output()
	if errorListingInterface != nil {
		fmt.Printf("Error in the network interfaces! Please Check.\n")
		log.Fatal(errorListingInterface)
	}
	var listOfInterfaces []string
	listOfInterfaces = strings.Split(string(allInterface), "\n")

	statusOfPath := "/sys/class/net/" + networkInterfaceNameFromYaml + "/device/sriov_numvfs"
	_, errorPath := os.Stat(statusOfPath)
	if errorPath == nil {
		networkInterface = networkInterfaceNameFromYaml
	} else {
		fmt.Println("Provided interface name does not exist!")
		for i := 0; i < len(listOfInterfaces); i++ {
			statusOfPath := "/sys/class/net/" + listOfInterfaces[i] + "/device/sriov_numvfs"
			_, errorPath := os.Stat(statusOfPath)
			if errorPath == nil {
				showNumberOfVFs := "cat /sys/class/net/" + listOfInterfaces[i] + "/device/sriov_numvfs"
				numberOfVFsOutput, _ := exec.Command("bash", "-c", showNumberOfVFs).Output()
				var listNumberOfVFsOutput []string
				listNumberOfVFsOutput = strings.Split(string(numberOfVFsOutput), "\n")
				VFAssigned := listNumberOfVFsOutput[0]
				strToInt, _ := strconv.Atoi(VFAssigned)
				if strToInt > 0 {
					networkInterface = listOfInterfaces[i]
					break
				}
			}
		}
	}
	if networkInterface == "" {
		fmt.Printf("Error in SRIOV VFs Config! Please Check.\n")
	}
	return networkInterface
}

//Reads Yaml file for SRIOV interface information
func parseParametersFromYaml() bool {
	yamlFile, _ := ioutil.ReadFile(secondary_network_config_path + configFile[0])
	structureOfYaml := make(map[string]secondary_network_config)
	errorYamlUnmarshal := yaml.Unmarshal(yamlFile, &structureOfYaml)
	if errorYamlUnmarshal != nil {
		log.Fatal(errorYamlUnmarshal)
	}
	sriovConfig := structureOfYaml["sriov_conf"]
	vnConfig := structureOfYaml["vir_net"]
	podConfig := structureOfYaml["create_pod"]

	// Network Interface specifications
	networkInterfaceNameFromYaml := sriovConfig.NetworkInterface
	totalNumberOfVirtualFunctions = sriovConfig.NumberOfVFs

	if networkInterfaceNameFromYaml == "" {
		fmt.Errorf("Network interface is not provided in the secondary_network_configuration.yaml file")
		networkInterfaceName = checkNetworkInterface(networkInterfaceNameFromYaml)
	} else {
		networkInterfaceName = checkNetworkInterface(networkInterfaceNameFromYaml)
	}

	totalNumberOfVirtualFunctions = sriovConfig.NumberOfVFs
	// Virtual Network specifications - number of VN and it's names
	vnLength := len(vnConfig.VirtualNetworkNames)
	totalVirtualNetworks = vnConfig.TotalNumberOfVirtualNetworks

	for i := 0; i < vnLength; i++ {
		nameOfVirtualNetwork[i] = vnConfig.VirtualNetworkNames[i]
	}
	//Number of pods to be created
	totalNumberOfPods = podConfig.NumberOfPods

	//Name of the yaml files
	for m := 0; m < totalNumberOfPods; m++ {
		nameOfYamlPerPod[m] = podConfig.PodYamlFiles[m]
	}

	//Number of virtual networks in each pod
	listOfVNLength := len(podConfig.NumberOfVirtualNetworksPerPod)
	for k := 0; k < listOfVNLength; k++ {
		listOfVirtualNetworksPerPod[k] = podConfig.NumberOfVirtualNetworksPerPod[k]

		//Names of virtual networks in the each pod
		nameOfVNLength := len(podConfig.PodVirtualNetworkNames)
		for i := 0; i < nameOfVNLength; i++ {
			var nameOfVNPerPodLength = len(podConfig.PodVirtualNetworkNames[i])
			for j := 0; j < nameOfVNPerPodLength; j++ {
				nameOfVirtualNetworkPerPod[i][j] = podConfig.PodVirtualNetworkNames[i][j]
			}
		}

		//Names of each pod
		for j := 0; j < totalNumberOfPods; j++ {
			nameOfPods[j] = podConfig.PodNames[j]
		}

		//Interface name for each pod
		interfaceListLength := len(podConfig.PodInterfaceNames)
		for i := 0; i < interfaceListLength; i++ {
			var InterfacePerPodLength = len(podConfig.PodInterfaceNames[i])
			for j := 0; j < InterfacePerPodLength; j++ {
				nameOfInterfacePerPod[i][j] = podConfig.PodInterfaceNames[i][j]
			}
		}
	}
	return true
}

//configures SRIOV with the number of virtual functions specified in the secondary_network_params.yaml file.
func configureSriovVFs(networkInterfaceName string, numberOfVirtualFunctions string) bool {
	configureVF := "echo '" + numberOfVirtualFunctions + "' > /sys/class/net/" + networkInterfaceName + "/device/sriov_numvfs"
	configureVFToConsole := exec.Command("sudo", "bash", "-c", configureVF)
	configureVFToConsole.Stdin = os.Stdin
	configureVFToConsole.Stdout = os.Stdout
	configureVFToConsole.Stderr = os.Stderr
	errorConfigureVF := configureVFToConsole.Start()
	if errorConfigureVF != nil {
		fmt.Errorf("Error in Configuring the Virtual Functions! Please Check.\n")
		log.Fatal(errorConfigureVF)
	}
	errorConfigureVFWait := configureVFToConsole.Wait()
	if errorConfigureVFWait != nil {
		fmt.Errorf("Error in Configuring the Virtual Functions! Please Check.\n")
		log.Fatal(errorConfigureVFWait)
	}
	return true
}

// This function sets up the IP link and brings up the Network Interface to the system.
func setIPLinkUp(networkInterfaceName string) bool {
	_, errorIPLinkSet := exec.Command("ip", "link", "set", networkInterfaceName, "up").Output()
	if errorIPLinkSet != nil {
		fmt.Errorf("Error in setting network interface IP link Up! Please Check.\n")
		log.Fatal(errorIPLinkSet)
	}
	return true
}

// This function sets the IP link down of the Network Interface to the system.
func setIPLinkDown(networkInterfaceName string) bool {
	_, errIPLinkSet := exec.Command("ip", "link", "set", networkInterfaceName, "down").Output()
	if errIPLinkSet != nil {
		fmt.Errorf("Error in setting network interface IP link Down! Please Check.\n")
		log.Fatal(errIPLinkSet)
	}
	return true
}

// Checks the logs of the pods while creating them and while deploying the antrea.
// Useful in checking if there are any crashes or errors
func captureLogs() {
	getAllPods, _ := exec.Command("kubectl", "get", "pods", "-n", "kube-system").Output()
	var listAllPods []string
	var getLogs string
	listAllPods = strings.Split(string(getAllPods), "\n")
	getAntreaAgentName := strings.Split(listAllPods[1], " ")

	// Extract antrea-agent name and dumping the logs to sanity.log file
	getLogs = "kubectl logs " + getAntreaAgentName[0] + " -c antrea-agent -n kube-system >> " + LogFileName + " &"
	logsToConsole := exec.Command("bash", "-c", getLogs)
	logsToConsole.Stdin = os.Stdin
	logsToConsole.Stdout = os.Stdout
	logsToConsole.Stderr = os.Stderr
	errorLogs := logsToConsole.Start()
	if errorLogs != nil {
		fmt.Errorf("Error in getting logs! Please Check.\n")
		log.Fatal(errorLogs)
	}
	errorLogsWait := logsToConsole.Wait()
	if errorLogsWait != nil {
		fmt.Errorf("Error in getting logs! Please Check.\n")
		log.Fatal(errorLogsWait)
	}
}

// apply the sriov-network device plugin configMap and deamonSet to the system.
func deploySriovPlugin() (string, string) {
	var pathOfSriovConfigMap string
	var pathOfSriovDaemonSet string
	pathOfSriovConfigMap = secondary_network_config_path + configFile[4]
	applySriovConfigMap, errorConfigMap := exec.Command("kubectl", "apply", "-f", pathOfSriovConfigMap).Output()
	if errorConfigMap != nil {
		fmt.Errorf("Error in applying sriov-network-device-plugin ConfigMap Yaml file! Please Check.\n")
		log.Fatal(errorConfigMap)
	}
	pathOfSriovDaemonSet = secondary_network_config_path + configFile[5]
	applySriovDaemonSet, errorDaemonSet := exec.Command("kubectl", "apply", "-f", pathOfSriovDaemonSet).Output()
	if errorDaemonSet != nil {
		fmt.Errorf("Error in applying sriov-network-device-plugin DaemonSet Yaml file! Please Check.\n")
		log.Fatal(errorDaemonSet)
	}
	var output1, output2 string
	output1 = string(applySriovConfigMap)
	output2 = string(applySriovDaemonSet)
	return output1, output2
}

// configure the Network Attachment Definition YAML file to the system
func configNetAttachDefinition() string {
	var pathNetAttachDefinition string
	pathNetAttachDefinition = secondary_network_config_path + configFile[1]
	applyNetAttachDefinition, errorNetAttachDefinition := exec.Command("kubectl", "apply", "-f", pathNetAttachDefinition).Output()
	if errorNetAttachDefinition != nil {
		fmt.Errorf("Error in applying network attachment definition Yaml file! Please Check.\n")
		log.Fatal(errorNetAttachDefinition)
	}
	output1 := string(applyNetAttachDefinition)
	return output1
}

// Applies the virtual network yaml files to the system
func deployVirtualNetworks(totalVirtualNetworks int, nameOfVirtualNetwork [20]string) bool {
	for i := 0; i < totalVirtualNetworks; i++ {
		var pathOfVirtualNetwork string
		pathOfVirtualNetwork = secondary_network_config_path + nameOfVirtualNetwork[i]
		_, errorVirtualNetwork := exec.Command("kubectl", "apply", "-f", pathOfVirtualNetwork, "-n", "kube-system").Output()
		if errorVirtualNetwork != nil {
			fmt.Errorf("Error in applying %s Yaml file! Please Check.\n", nameOfVirtualNetwork[i])
			log.Fatal(errorVirtualNetwork)
		}
	}
	return true
}

// Configures the whereabouts IPpools to the system
func configWhereabouts() string {
	var pathOfWhereabouts string
	pathOfWhereabouts = secondary_network_config_path + configFile[2]
	applyWhereabouts, errorConfigWhereabouts := exec.Command("kubectl", "apply", "-f", pathOfWhereabouts).Output()
	if errorConfigWhereabouts != nil {
		fmt.Errorf("Error in Configuring whereabouts! Please Check.\n")
		log.Fatal(errorConfigWhereabouts)
	}
	output1 := string(applyWhereabouts)
	return output1
}

// deploy the Antrea CNI and configures it
func deployAntreaCNI() bool {
	var pathOfAntreaCni string
	pathOfAntreaCni = secondary_network_config_path + configFile[3]
	_, errorAntreaCni := exec.Command("kubectl", "apply", "-f", pathOfAntreaCni).Output()
	if errorAntreaCni != nil {
		fmt.Errorf("Error in Deploying Antrea CNI! Please Check.\n")
		log.Fatal(errorAntreaCni)
	}
	exec.Command("sleep", "5").Output()
	file, errorLogFile := os.OpenFile(LogFileName, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if errorLogFile != nil {
		fmt.Errorf("Could not open Sanity log file")
	}
	_, errorWriteFile := file.WriteString("\n\n\n Deployment to antrea CNI logs: \n\n\n\n\n\n")
	if errorWriteFile != nil {
		fmt.Errorf("Could not write logs to the sanity log file!!")
	}
	defer file.Close()
	captureLogs()
	return true
}

// Generates the pod yaml files for the creation of the pod
func generatePodYaml(totalNumberOfPods int, listOfVirtualNetworksPerPod [20]int, nameOfVirtualNetworkPerPod [20][20]string, nameOfInterfacePerPod [20][20]string, nameOfYamlPerPod [20]string, nameOfPods [20]string) bool {
	var VirtualNetworkName = ""
	var InterfaceName = ""
	var Input = ""
	// Generating yaml files for all the pods
	for j := 0; j < totalNumberOfPods; j++ {
		// Formation of annotation string of each pod yaml
		var annotation_str = ""
		for i := 0; i < listOfVirtualNetworksPerPod[j]; i++ {
			VirtualNetworkName = nameOfVirtualNetworkPerPod[j][i]
			InterfaceName = nameOfInterfacePerPod[j][i]
			Input = "{\"name\": \"" + VirtualNetworkName + "\" ,\"interface\": \"" + InterfaceName + "\" , \"type\": \"sriov\"}"
			//fmt.Println(str)
			if annotation_str == "" {
				annotation_str = "[" + Input
			} else {
				annotation_str = annotation_str + "," + Input
			}
		}
		annotation_str = annotation_str + "]"
		// Formation of Pod Spec, Metadata, kind and version
		podSpecObj := PodYamlFile{APIVersion: "v1",
			Kind:     "Pod",
			Metadata: Metadata{Annotations: Annotations{K8SV1CniCncfIoNetworks: annotation_str}, Labels: Labels{App: "testsecpod"}, Name: nameOfPods[j]},
			Spec: Spec{Containers: [1]Containers{{Image: "busybox", ImagePullPolicy: "IfNotPresent", Command: []string{"sleep"}, Args: []string{"infinity"}, Name: "busyboxpod",
				Resources: Resources{Requests: Requests{IntelComIntelSriovNetdevice: "3"}, Limits: Limits{IntelComIntelSriovNetdevice: "3"}}}}, RestartPolicy: "OnFailure"}}

		data, errorYamlMarshal := yaml.Marshal(&podSpecObj)
		if errorYamlMarshal != nil {
			log.Fatal(errorYamlMarshal)
		}
		errorWriteYaml := ioutil.WriteFile(nameOfYamlPerPod[j], data, 0)
		if errorWriteYaml != nil {
			fmt.Errorf("Error in writing to yaml file! Please Check.\n")
			log.Fatal(errorWriteYaml)
		}
	}
	return true
}

// Creates the pods in the system and add logs for the same in the sanity.log file
func createPods() bool {
	for podIndex := 0; podIndex < totalNumberOfPods; podIndex++ {
		// Enabling Logs before creating the pod
		file, openLog := os.OpenFile(LogFileName, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
		if openLog != nil {
			fmt.Errorf("Could not open Sanity log file")
		}
		_, errorWriteLog := file.WriteString("\n\n\n Adding logs while pod creation: " + nameOfPods[podIndex] + "\n\n\n\n\n\n")
		if errorWriteLog != nil {
			fmt.Errorf("Could not write logs to the sanity log file!!")
		}
		defer file.Close()
		captureLogs()

		// Creating the pods
		if _, errorStatusYaml := os.Stat(nameOfYamlPerPod[podIndex]); errorStatusYaml == nil {
			fmt.Println("Test pod creating with " + nameOfYamlPerPod[podIndex])
			_, errorCreatePod := exec.Command("kubectl", "apply", "-f", nameOfYamlPerPod[podIndex], "-n", "kube-system").Output()
			exec.Command("sleep", "7").Output()
			if errorCreatePod != nil {
				fmt.Errorf("Error in creating pod with yaml name %s ! Please Check.\n", nameOfYamlPerPod[podIndex])
				log.Fatal(errorCreatePod)
			}
		} else {
			fmt.Errorf("Pod yaml file does not exist!\n")
		}
	}

	// Display the created pods
	displayPods, errorGetPods := exec.Command("kubectl", "get", "pods", "-o", "wide", "-n", "kube-system").Output()
	if errorGetPods != nil {
		fmt.Errorf("Error in getting pods! Please Check.\n")
		log.Fatal(errorGetPods)
	} else {
		fmt.Printf("%s", displayPods)
	}
	return true
}

//  This function checks the secondary interface IP addresses
func checkSecIPs() bool {
	for podIndex := 0; podIndex < totalNumberOfPods; podIndex++ {
		fmt.Printf("\n-------------------------------------------\n")
		fmt.Printf("IP addresses of the pod: %s \n\n", nameOfPods[podIndex])
		showIPAddress, errorCheckIP := exec.Command("kubectl", "exec", "-it", nameOfPods[podIndex], "-n", "kube-system", "--", "ip", "addr", "show").Output()
		if errorCheckIP != nil {
			fmt.Printf("Error in checking the secondary interface IPs! Please Check.\n")
			captureLogs()
			antreaCleanup()
			log.Fatal(errorCheckIP)
		} else {
			fmt.Printf("%s", showIPAddress)
		}
	}
	return true
}

// Deletes pods created in the system and add logs for the same
func deletePod() bool {
	for podIndex := 0; podIndex < totalNumberOfPods; podIndex++ {
		// Enabling Logs before deleting the pod
		file, errorOpenFile := os.OpenFile(LogFileName, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
		if errorOpenFile != nil {
			fmt.Errorf("Could not open Sanity log file")
		}
		_, errorWriteString := file.WriteString("\n\n\n Adding logs while pod deletion: " + nameOfPods[podIndex] + "\n\n\n\n\n\n")
		if errorWriteString != nil {
			fmt.Errorf("Could not write logs to the sanity log file!!")
		}
		defer file.Close()
		captureLogs()

		// Deleting the pods
		if _, errorStatusYaml := os.Stat(nameOfYamlPerPod[podIndex]); errorStatusYaml == nil {
			fmt.Println("Test pod deleting with " + nameOfYamlPerPod[podIndex])
			_, errorDeletePod := exec.Command("kubectl", "delete", "pod", nameOfPods[podIndex], "-n", "kube-system").Output()
			exec.Command("sleep", "15").Output()
			if errorDeletePod != nil {
				fmt.Errorf("Error in deleting pod %s ! Please Check.\n", nameOfPods[podIndex])
				log.Fatal(errorDeletePod)
			}
		} else {
			fmt.Errorf("Pod yaml file does not exist!\n")
		}
	}
	exec.Command("sleep", "15").Output()

	// Displaying after deleting pods
	getPods, errorGetPods := exec.Command("kubectl", "get", "pods", "-o", "wide", "-n", "kube-system").Output()
	if errorGetPods != nil {
		fmt.Errorf("Error in getting all pods! Please Check.\n")
		log.Fatal(errorGetPods)
	} else {
		fmt.Printf("%s", getPods)
	}
	return true
}

// Deletes the configured network attachment definition file
func deleteNetAttachDefinition() bool {
	var pathOfNetAttachDefinition string
	pathOfNetAttachDefinition = secondary_network_config_path + configFile[1]
	_, errorDeleteNetAttachDef := exec.Command("kubectl", "delete", "-f", pathOfNetAttachDefinition).Output()
	if errorDeleteNetAttachDef != nil {
		fmt.Errorf("Error in deleting network attachment definition yaml file! Please Check.\n")
		log.Fatal(errorDeleteNetAttachDef)
	}
	return true
}

// Delete  the sriov-network device plugin configMap and deamonSet to the system.
func deleteSriovPlugin() (string, string) {
	var pathOfSriovConfigMap string
	var pathOfSriovDaemonSet string
	pathOfSriovConfigMap = secondary_network_config_path + configFile[4]
	applySriovConfigMap, errorConfigMap := exec.Command("kubectl", "delete", "-f", pathOfSriovConfigMap).Output()
	if errorConfigMap != nil {
		fmt.Errorf("Error in deleting sriov-network-device-plugin ConfigMap Yaml file! Please Check.\n")
		log.Fatal(errorConfigMap)
	}
	pathOfSriovDaemonSet = secondary_network_config_path + configFile[5]
	applySriovDaemonSet, errorDaemonSet := exec.Command("kubectl", "delete", "-f", pathOfSriovDaemonSet).Output()
	if errorDaemonSet != nil {
		fmt.Errorf("Error in deleting sriov-network-device-plugin DaemonSet Yaml file! Please Check.\n")
		log.Fatal(errorDaemonSet)
	}
	var outputSriovConfigMap, outputSriovDaemonSet string
	outputSriovConfigMap = string(applySriovConfigMap)
	outputSriovDaemonSet = string(applySriovDaemonSet)
	return outputSriovConfigMap, outputSriovDaemonSet
}

//Deletes the applied Virtual networks
func deleteVirtualNetworks(totalVirtualNetworks int, nameOfVirtualNetwork [20]string) bool {
	for i := 0; i < totalVirtualNetworks; i++ {
		var pathOfVirtualNetworks string
		pathOfVirtualNetworks = secondary_network_config_path + nameOfVirtualNetwork[i]
		_, errorDeleteVN := exec.Command("kubectl", "delete", "-f", pathOfVirtualNetworks, "-n", "kube-system").Output()
		if errorDeleteVN != nil {
			fmt.Errorf("Error in virtual network yaml file %s ! Please Check.\n", nameOfVirtualNetwork[i])
			log.Fatal(errorDeleteVN)
		}
	}
	return true
}

// Deconfigures the Whereabouts IPPool through the yaml file
func deconfigWhereabouts() bool {
	var pathOfWhereabouts string
	pathOfWhereabouts = secondary_network_config_path + configFile[2]
	_, errorWhereabouts := exec.Command("kubectl", "delete", "-f", pathOfWhereabouts).Output()
	if errorWhereabouts != nil {
		fmt.Errorf("Error in Deconfiguring whereabouts! Please Check.\n")
		log.Fatal(errorWhereabouts)
	}
	return true
}

// Deletes the Antrea CNI applied
func deleteAntreaCNI() bool {
	var pathOfAntreaCni string
	pathOfAntreaCni = secondary_network_config_path + configFile[3]
	_, errorDeleteAntreaCni := exec.Command("kubectl", "delete", "-f", pathOfAntreaCni).Output()
	if errorDeleteAntreaCni != nil {
		fmt.Errorf("Error in Deploying Antrea CNI! Please Check.\n")
		log.Fatal(errorDeleteAntreaCni)
	}
	return true
}

// Delete pod yaml files
func deletePodYamlFiles() bool {
	commandDeletePodYaml := "rm -f  sanity*.yaml"
	outputDeletePodYaml := exec.Command("sudo", "bash", "-c", commandDeletePodYaml)
	outputDeletePodYaml.Stdin = os.Stdin
	outputDeletePodYaml.Stdout = os.Stdout
	outputDeletePodYaml.Stderr = os.Stderr
	errorDeletePodYaml := outputDeletePodYaml.Start()
	if errorDeletePodYaml != nil {
		fmt.Printf("Error in deleting the pod yaml files! Please Check.\n")
		log.Fatal(errorDeletePodYaml)
	} else {
		fmt.Println("\nDeleted pod yaml files successfully!...")
	}
	return true
}

// This function cleans up all the things created while execution
func antreaCleanup() {
	deletePod()
	deletePodYamlFiles()
	deleteAntreaCNI()
	deconfigWhereabouts()
	deleteVirtualNetworks(totalVirtualNetworks, nameOfVirtualNetwork)
	deleteNetAttachDefinition()
	deleteSriovPlugin()
	configureSriovVFs(networkInterfaceName, "0")
	setIPLinkDown(networkInterfaceName)
	getPods, _ := exec.Command("kubectl", "get", "pods", "-n", "kube-system").Output()
	fmt.Printf("\n\n%s", getPods)
}

//////////////////////////////////////////////////////////
///              TEST FUNCTIONS                        ///
//////////////////////////////////////////////////////////

// Test function for StartSanity function
func TestStartSanity(t *testing.T) {
	actualOutput := startSanity(100)
	expectedOutput := 100
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%d) is not same as"+" actual string (%d)", expectedOutput, actualOutput)
	}
}

// Test function for ParseParmYaml function
func TestParseParametersFromYaml(t *testing.T) {
	actualOutput := parseParametersFromYaml()
	expectedOutput := true
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput)
	}
}

// Test function for SriovConfVFS function
func TestConfigureSriovVFs(t *testing.T) {
	checkVFs := "cat /sys/class/net/" + networkInterfaceName + "/device/sriov_numvfs"
	showVFsAtConsole, _ := exec.Command("bash", "-c", checkVFs).Output()
	var listVF []string
	listVF = strings.Split(string(showVFsAtConsole), "\n")
	VFAssigned := listVF[0]
	if VFAssigned != totalNumberOfVirtualFunctions {
		actualOutput := configureSriovVFs(networkInterfaceName, "0")
		expectedOutput := true
		if actualOutput != expectedOutput {
			t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput)
		}
		// Setting IP link Down
		actualOutput2 := setIPLinkDown(networkInterfaceName)
		expectedOutput2 := true
		if actualOutput2 != expectedOutput2 {
			t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput2, actualOutput2)
		}
		actualOutput1 := configureSriovVFs(networkInterfaceName, totalNumberOfVirtualFunctions)
		// Validation of VFs
		showVFs := "cat /sys/class/net/" + networkInterfaceName + "/device/sriov_numvfs"
		showVFsAtConsole := exec.Command("sudo", "bash", "-c", showVFs)
		showVFsAtConsole.Stdin = os.Stdin
		showVFsAtConsole.Stdout = os.Stdout
		showVFsAtConsole.Stderr = os.Stderr
		errorShowVF := showVFsAtConsole.Start()
		if errorShowVF != nil {
			fmt.Printf("Error in showing the Configured Virtual Functions! Please Check.\n")
			log.Fatal(errorShowVF)
		}
		errorShowVFWait := showVFsAtConsole.Wait()
		if errorShowVFWait != nil {
			log.Fatal(errorShowVFWait)
		}
		expectedOutput1 := true
		if actualOutput1 != expectedOutput1 {
			t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput1, actualOutput1)
		}
		// Setting IP link up
		actualOutput3 := setIPLinkUp(networkInterfaceName)
		expectedOutput3 := true
		if actualOutput3 != expectedOutput3 {
			t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput3, actualOutput3)
		}
	}
}

// Test function for DeploySriovPlugin function
func TestDeploySriovPlugin(t *testing.T) {
	deploySriovPlugin()
	actualOutput1, actualOutput2 := deploySriovPlugin()
	expectedOutput1 := "configmap/sriovdp-config unchanged\n"

	expectedOutput2 := `serviceaccount/sriov-device-plugin unchanged
daemonset.apps/kube-sriov-device-plugin-amd64 configured
daemonset.apps/kube-sriov-device-plugin-ppc64le configured
daemonset.apps/kube-sriov-device-plugin-arm64 configured
`
	if actualOutput1 != expectedOutput1 {
		t.Errorf("Expected String(%s) is not same as"+" actual string (%s)", expectedOutput1, actualOutput1)
	}
	if actualOutput2 != expectedOutput2 {
		t.Errorf("Expected String(%s) is not same as"+" actual string (%s)", expectedOutput1, actualOutput2)
	}
}

// Test function for ConfigNetAttachDefinition function
func TestConfigNetAttachDefinition(t *testing.T) {
	configNetAttachDefinition()
	actualOutput := configNetAttachDefinition()
	expectedOutput := "customresourcedefinition.apiextensions.k8s.io/network-attachment-definitions.k8s.cni.cncf.io unchanged\n"
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%s) is not same as"+" actual string (%s)", expectedOutput, actualOutput)
	}
}

// Test function for ConfigWhereabouts function
func TestConfigWhereabouts(t *testing.T) {
	configWhereabouts()
	actualOutput := configWhereabouts()
	expectedOutput := "customresourcedefinition.apiextensions.k8s.io/ippools.whereabouts.cni.cncf.io configured\n"
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%s) is not same as"+" actual string (%s)", expectedOutput, actualOutput)
	}
}

// Test function for DeployVirtualNetworks function
func TestDeployVirtualNetworks(t *testing.T) {
	actualOutput := deployVirtualNetworks(totalVirtualNetworks, nameOfVirtualNetwork)
	expectedOutput := true
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actualOutput string (%t)", expectedOutput, actualOutput)
	}
}

// Test function for DeployAntreaCni function
func TestDeployAntreaCNI(t *testing.T) {
	actualOutput := deployAntreaCNI()
	expectedOutput := true
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput)
	}
}

// Test function for Generate_Yaml function
func TestGeneratePodYaml(t *testing.T) {
	actualOutput := generatePodYaml(totalNumberOfPods, listOfVirtualNetworksPerPod, nameOfVirtualNetworkPerPod, nameOfInterfacePerPod, nameOfYamlPerPod, nameOfPods)
	expectedOutput := true
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput)
	}
}

// Test function for CreatePods function
func TestCreatePods(t *testing.T) {
	actualOutput := createPods()
	expectedOutput := true
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput)
	}
}

// Test function for CheckSecIPS function
func TestCheckSecIPs(t *testing.T) {
	actualOutput := checkSecIPs()
	expectedOutput := true
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput)
	}
}

// Test function for DeletePod function
func TestDeletePod(t *testing.T) {
	actualOutput := deletePod()
	expectedOutput := true
	if actualOutput != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput)
	}
}

// Test function for DeleteSriovPlugin function
func TestDeleteSriovPlugin(t *testing.T) {
	actualOutput1, actualOutput2 := deleteSriovPlugin()
	expectedOutput1 := "configmap \"sriovdp-config\" deleted\n"

	expectedOutput2 := `serviceaccount "sriov-device-plugin" deleted
daemonset.apps "kube-sriov-device-plugin-amd64" deleted
daemonset.apps "kube-sriov-device-plugin-ppc64le" deleted
daemonset.apps "kube-sriov-device-plugin-arm64" deleted
`
	if actualOutput1 != expectedOutput1 {
		t.Errorf("Expected String(%s) is not same as"+" actual string (%s)", expectedOutput1, actualOutput1)
	}
	if actualOutput2 != expectedOutput2 {
		t.Errorf("Expected String(%s) is not same as"+" actual string (%s)", expectedOutput1, actualOutput2)
	}
}

// Test function for AntreaCleanUp i.e deleting virtual networks, network attachment definition file, deleting antrea CNI and whereabouts IP Pools
func TestAntreaCleanUp(t *testing.T) {
	// Deleting VirtualNetworks
	actualOutput1 := deleteVirtualNetworks(totalVirtualNetworks, nameOfVirtualNetwork)
	expectedOutput := true
	if actualOutput1 != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput1)
	}
	// Deconfig Whereabouts
	actualOutput2 := deconfigWhereabouts()
	if actualOutput2 != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput2)
	}
	// Deleting NetAttachDefinition
	actualOutput3 := deleteNetAttachDefinition()
	if actualOutput3 != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput3)
	}
	// Deconfig SRIOV VFs
	actualOutput4 := configureSriovVFs(networkInterfaceName, "0")
	if actualOutput4 != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput4)
	}
	//Setting IP Link Down
	actualOutput5 := setIPLinkDown(networkInterfaceName)
	if actualOutput5 != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput5)
	}
	// Delete pod yaml files
	actualOutput6 := deletePodYamlFiles()
	if actualOutput6 != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput6)
	}
	/* // Deleting Antrea CNI
	actualOutput7 := deleteAntreaCNI()
	if actualOutput7 != expectedOutput {
		t.Errorf("Expected String(%t) is not same as"+" actual string (%t)", expectedOutput, actualOutput7)
	} */
}
