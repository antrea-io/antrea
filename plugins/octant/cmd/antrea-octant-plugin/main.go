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

package main

import (
	"context"
	"log"
	"os"
	"strconv"

	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"

	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

var (
	pluginName                      = "antrea-octant-plugin"
	client     *clientset.Clientset = nil
)

const (
	kubeConfig      = "KUBECONFIG"
	title           = "Antrea Information"
	controllerTitle = "Antrea Controller Info"
	agentTitle      = "Antrea Agent Info"
	versionCol      = "Version"
	podCol          = "Pod"
	nodeCol         = "Node"
	serviceCol      = "Service"
	crdCol          = "Monitoring CRD"
	subnetCol       = "NodeSubnet"
	bridgeCol       = "OVS Bridge"
	podNumCol       = "Local Pod Num"
	heartbeatCol    = "Last Heartbeat Time"
)

func main() {
	// Remove the prefix from the go logger since Octant will print logs with timestamps.
	log.SetPrefix("")
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv(kubeConfig))
	if err != nil {
		log.Fatalf("Failed to build kubeConfig %v", err)
	}
	client, err = clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client for antrea-octant-plugin %v", err)
	}

	// This plugin is interested in AntreaControllerInfo and AntreaAgentInfo.
	antreaControllerInfoGVK := schema.GroupVersionKind{Version: "v1beta1", Kind: "AntreaControllerInfo"}
	antreaAgentInfoGVK := schema.GroupVersionKind{Version: "v1beta1", Kind: "AntreaAgentInfo"}

	capabilities := &plugin.Capabilities{
		SupportsPrinterConfig: []schema.GroupVersionKind{antreaControllerInfoGVK, antreaAgentInfoGVK},
		SupportsTab:           []schema.GroupVersionKind{antreaControllerInfoGVK, antreaAgentInfoGVK},
		IsModule:              true,
	}

	// Set up navigation services
	options := []service.PluginOption{
		service.WithNavigation(handleNavigation, initRoutes),
	}

	// Register this plugin.
	p, err := service.Register(pluginName, title, capabilities, options...)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("antrea-octant-plugin is starting")
	p.Serve()
}

// handleNavigation generates contents displayed on navigation bar and their paths.
func handleNavigation(request *service.NavigationRequest) (navigation.Navigation, error) {
	return navigation.Navigation{
		Title: title,
		Path:  request.GeneratePath("components"),
		Children: []navigation.Navigation{
			{
				Title:    controllerTitle,
				Path:     request.GeneratePath("components/controller"),
				IconName: "folder",
			},
			{
				Title:    agentTitle,
				Path:     request.GeneratePath("components/agent"),
				IconName: "folder",
			},
		},
		IconName: "cloud",
	}, nil
}

// initRoutes routes for Antrea plugin.
func initRoutes(router *service.Router) {
	controllerCols := component.NewTableCols(versionCol, podCol, nodeCol, serviceCol, crdCol, heartbeatCol)
	agentCols := component.NewTableCols(versionCol, podCol, nodeCol, subnetCol, bridgeCol, podNumCol, crdCol, heartbeatCol)

	// Click on navigation bar named Antrea Information to display Antrea components (both Controller and Agent) information.
	router.HandleFunc("/components", func(request service.Request) (component.ContentResponse, error) {
		controllerRows := getControllerRows()
		agentRows := getAgentRows()
		return component.ContentResponse{
			Title: component.TitleFromString(title),
			Components: []component.Component{
				component.NewTableWithRows(controllerTitle, "", controllerCols, controllerRows),
				component.NewTableWithRows(agentTitle, "", agentCols, agentRows),
			},
		}, nil
	})

	// Click on navigation child named Antrea Controller Info to display Controller information.
	router.HandleFunc("/components/controller", func(request service.Request) (component.ContentResponse, error) {
		controllerRows := getControllerRows()
		return component.ContentResponse{
			Title: component.TitleFromString(controllerTitle),
			Components: []component.Component{
				component.NewTableWithRows(controllerTitle, "", controllerCols, controllerRows),
			},
		}, nil
	})

	// Click on navigation child named Antrea Agent Info to display Agent information.
	router.HandleFunc("/components/agent", func(request service.Request) (component.ContentResponse, error) {
		agentRows := getAgentRows()
		return component.ContentResponse{
			Title: component.TitleFromString(agentTitle),
			Components: []component.Component{
				component.NewTableWithRows(agentTitle, "", agentCols, agentRows),
			},
		}, nil
	})
}

// getControllerRows gets rows for displaying Controller information
func getControllerRows() []component.TableRow {
	controllers, err := client.ClusterinformationV1beta1().AntreaControllerInfos().List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Fatalf("Failed to get AntreaControllerInfos %v", err)
	}
	controllerRows := make([]component.TableRow, 0)
	for _, controller := range controllers.Items {
		controllerRows = append(controllerRows, component.TableRow{
			versionCol: component.NewText(controller.Version),
			podCol: component.NewLink(controller.PodRef.Name, controller.PodRef.Name,
				"/overview/namespace/"+controller.PodRef.Namespace+"/workloads/pods/"+controller.PodRef.Name),
			nodeCol: component.NewLink(controller.NodeRef.Name, controller.NodeRef.Name,
				"/cluster-overview/nodes/"+controller.NodeRef.Name),
			serviceCol: component.NewLink(controller.ServiceRef.Name, controller.ServiceRef.Name,
				"/overview/namespace/"+controller.PodRef.Namespace+"/discovery-and-load-balancing/services/"+controller.ServiceRef.Name),
			crdCol: component.NewLink(controller.Name, controller.Name,
				"/cluster-overview/custom-resources/antreacontrollerinfos.clusterinformation.antrea.tanzu.vmware.com/"+controller.Name),
			heartbeatCol: component.NewText(controller.ControllerConditions[0].LastHeartbeatTime.String()),
		})
	}
	return controllerRows
}

// getAgentRows gets table rows for displaying Agent information.
func getAgentRows() []component.TableRow {
	agents, err := client.ClusterinformationV1beta1().AntreaAgentInfos().List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Fatalf("Failed to get AntreaAgentInfos %v", err)
	}
	agentRows := make([]component.TableRow, 0)
	for _, agent := range agents.Items {
		agentRows = append(agentRows, component.TableRow{
			versionCol: component.NewText(agent.Version),
			podCol: component.NewLink(agent.PodRef.Name, agent.PodRef.Name,
				"/overview/namespace/"+agent.PodRef.Namespace+"/workloads/pods/"+agent.PodRef.Name),
			nodeCol: component.NewLink(agent.NodeRef.Name, agent.NodeRef.Name,
				"/cluster-overview/nodes/"+agent.NodeRef.Name),
			subnetCol: component.NewText(agent.NodeSubnet[0]),
			bridgeCol: component.NewText(agent.OVSInfo.BridgeName),
			podNumCol: component.NewText(strconv.Itoa(int(agent.LocalPodNum))),
			crdCol: component.NewLink(agent.Name, agent.Name,
				"/cluster-overview/custom-resources/antreaagentinfos.clusterinformation.antrea.tanzu.vmware.com/"+agent.Name),
			heartbeatCol: component.NewText(agent.AgentConditions[0].LastHeartbeatTime.String()),
		})
	}
	return agentRows
}
