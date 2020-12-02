// Copyright 2020 Antrea Authors
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
	"strconv"
	"strings"

	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	controllerTitle = "Controller Info"
	agentTitle      = "Agent Info"

	versionCol        = "Version"
	podCol            = "Pod"
	nodeCol           = "Node"
	serviceCol        = "Service"
	clusterInfoCrdCol = "Monitoring CRD"
	subnetsCol        = "NodeSubnets"
	bridgeCol         = "OVS Bridge"
	podNumCol         = "Local Pod Num"
	heartbeatCol      = "Last Heartbeat Time"
)

func (p *antreaOctantPlugin) controllerHandler(request service.Request) (component.ContentResponse, error) {
	return component.ContentResponse{
		Title: component.TitleFromString(controllerTitle),
		Components: []component.Component{
			p.getControllerTable(request),
		},
	}, nil
}

func (p *antreaOctantPlugin) agentHandler(request service.Request) (component.ContentResponse, error) {
	return component.ContentResponse{
		Title: component.TitleFromString(agentTitle),
		Components: []component.Component{
			p.getAgentTable(request),
		},
	}, nil
}

// getControllerTable gets the table for displaying Controller information
func (p *antreaOctantPlugin) getControllerTable(request service.Request) *component.Table {
	controllers, err := p.client.ClusterinformationV1beta1().AntreaControllerInfos().List(context.TODO(), v1.ListOptions{
		ResourceVersion: "0",
	})
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
			clusterInfoCrdCol: component.NewLink(controller.Name, controller.Name,
				"/cluster-overview/custom-resources/antreacontrollerinfos.clusterinformation.antrea.tanzu.vmware.com/v1beta1/"+controller.Name),
			heartbeatCol: component.NewText(controller.ControllerConditions[0].LastHeartbeatTime.String()),
		})
	}
	controllerCols := component.NewTableCols(versionCol, podCol, nodeCol, serviceCol, clusterInfoCrdCol, heartbeatCol)
	return component.NewTableWithRows(controllerTitle, "We couldn't find any Antrea controllers!", controllerCols, controllerRows)
}

// getAgentTable gets the table for displaying Agent information.
func (p *antreaOctantPlugin) getAgentTable(request service.Request) *component.Table {
	agents, err := p.client.ClusterinformationV1beta1().AntreaAgentInfos().List(context.TODO(), v1.ListOptions{
		ResourceVersion: "0",
	})
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
			subnetsCol: component.NewText(strings.Join(agent.NodeSubnets, ", ")),
			bridgeCol:  component.NewText(agent.OVSInfo.BridgeName),
			podNumCol:  component.NewText(strconv.Itoa(int(agent.LocalPodNum))),
			clusterInfoCrdCol: component.NewLink(agent.Name, agent.Name,
				"/cluster-overview/custom-resources/antreaagentinfos.clusterinformation.antrea.tanzu.vmware.com/v1beta1/"+agent.Name),
			heartbeatCol: component.NewText(agent.AgentConditions[0].LastHeartbeatTime.String()),
		})
	}
	agentCols := component.NewTableCols(versionCol, podCol, nodeCol, subnetsCol, bridgeCol, podNumCol, clusterInfoCrdCol, heartbeatCol)
	return component.NewTableWithRows(agentTitle, "We couldn't find any Antrea agents!", agentCols, agentRows)
}
