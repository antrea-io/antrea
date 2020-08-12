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

package graphviz

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/goccy/go-graphviz"
	"github.com/goccy/go-graphviz/cgraph"

	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
)

const (
	darkRed    = "#B20000"
	mistyRose  = "#EDD5D5"
	fireBrick  = "#B22222"
	ghostWhite = "#F8F8FF"
	gainsboro  = "#DCDCDC"
	lightGrey  = "#C8C8C8"
	silver     = "#C0C0C0"
	grey       = "#808080"
	dimGrey    = "#696969"
)

var (
	clusterSrcName = "cluster_source"
	clusterDstName = "cluster_destination"
)

func createNodeWithDefaultStyle(graph *cgraph.Graph, name string) *cgraph.Node {
	node, _ := graph.CreateNode(name)
	node.SetShape(cgraph.BoxShape)
	node.SetStyle(cgraph.RoundedNodeStyle + "," + cgraph.FilledNodeStyle + "," + cgraph.SolidNodeStyle)
	node.SetColor(dimGrey)
	return node
}

// EndpointNode is the the type of node for endpoints in networks like the sender and the receiver.
func createEndpointNodeWithDefaultStyle(graph *cgraph.Graph, name string) *cgraph.Node {
	node, _ := graph.CreateNode(name)
	node.SetColor(grey)
	node.SetFillColor(lightGrey)
	node.SetStyle(cgraph.FilledNodeStyle + "," + cgraph.BoldNodeStyle)
	return node
}

func createEdgeWithDefaultStyle(graph *cgraph.Graph, name string, start *cgraph.Node, end *cgraph.Node) *cgraph.Edge {
	edge, _ := graph.CreateEdge(name, start, end)
	edge.SetPenWidth(2.0)
	edge.SetColor(silver)
	return edge
}

// In Graphviz, cluster is a subgraph which is surrounded by a rectangle and the nodes belonging to the cluster are drawn together.
func createClusterWithDefaultStyle(graph *cgraph.Graph, name string) *cgraph.Graph {
	cluster := graph.SubGraph(name, 1)
	cluster.SetBackgroundColor(ghostWhite)
	cluster.SetStyle(cgraph.FilledGraphStyle + "," + cgraph.BoldGraphStyle)
	return cluster
}

func isSender(result *opsv1alpha1.NodeResult) bool {
	if len(result.Observations) == 0 {
		return false
	}
	if result.Observations[0].Component != opsv1alpha1.SpoofGuard || result.Observations[0].Action != opsv1alpha1.Forwarded {
		return false
	}
	return true
}

func isReceiver(result *opsv1alpha1.NodeResult) bool {
	if len(result.Observations) == 0 {
		return false
	}
	if result.Observations[0].Component != opsv1alpha1.Forwarding || result.Observations[0].Action != opsv1alpha1.Received {
		return false
	}
	return true
}

func getNodeResult(tf *opsv1alpha1.Traceflow, fn func(result *opsv1alpha1.NodeResult) bool) *opsv1alpha1.NodeResult {
	for _, result := range tf.Status.Results {
		if fn(&result) {
			return &result
		}
	}
	return nil
}

func getSrcNodeName(tf *opsv1alpha1.Traceflow) string {
	if len(tf.Spec.Source.Namespace) > 0 && len(tf.Spec.Source.Pod) > 0 {
		return tf.Spec.Source.Namespace + "/" + tf.Spec.Source.Pod
	}
	return ""
}

func getDstNodeName(tf *opsv1alpha1.Traceflow) string {
	if len(tf.Spec.Destination.Namespace) > 0 && len(tf.Spec.Destination.Pod) > 0 {
		return tf.Spec.Destination.Namespace + "/" + tf.Spec.Destination.Pod
	}
	if len(tf.Spec.Destination.Namespace) > 0 && len(tf.Spec.Destination.Service) > 0 {
		return tf.Spec.Destination.Namespace + "/" + tf.Spec.Destination.Service
	}
	if len(tf.Spec.Destination.IP) > 0 {
		return tf.Spec.Destination.IP
	}
	return ""
}

// getTraceflowMessage gets the shown message string in traceflow graph.
func getTraceflowMessage(o *opsv1alpha1.Observation) string {
	str := string(o.Component)
	if len(o.ComponentInfo) > 0 {
		str += "\n" + o.ComponentInfo
	}
	str += "\n" + string(o.Action)
	if o.Component == opsv1alpha1.NetworkPolicy && len(o.NetworkPolicy) > 0 {
		str += "\nNetpol: " + o.NetworkPolicy
	}
	if o.Action != opsv1alpha1.Dropped && len(o.TunnelDstIP) > 0 {
		str += "\nTo: " + o.TunnelDstIP
	}
	return str
}

// In Graphviz, clusters are surrounded by a pair of "{}" with string "subgraph ClusterName" before them.
// The function finds the start and end index of specific cluster.
func findClusterString(graphStr string, clusterName string) (startIndex int, endIndex int) {
	startIndex = strings.Index(graphStr, "subgraph "+clusterName)
	if startIndex == -1 {
		return 0, 1
	}
	endIndex = startIndex
	for graphStr[endIndex] != '{' {
		endIndex++
	}
	// Depth represents the number of "{" minus the number of "}" from the start index of current cluster to endIndex.
	// When depth is zero for the first time, it indicates that we successfully find the end index of the cluster.
	depth := 1
	for depth > 0 {
		endIndex++
		if graphStr[endIndex] == '{' {
			depth++
		}
		if graphStr[endIndex] == '}' {
			depth--
		}
	}
	return startIndex, endIndex + 1
}

func genOutput(g *graphviz.Graphviz, graph *cgraph.Graph, isSingleCluster bool) string {
	var buf bytes.Buffer
	if err := g.Render(graph, "dot", &buf); err != nil {
		log.Fatal(err)
	}
	if err := graph.Close(); err != nil {
		log.Fatal(err)
	}
	if err := g.Close(); err != nil {
		log.Fatal(err)
	}

	str := buf.String()
	if isSingleCluster {
		return str
	}
	// Swap source and destination cluster if destination cluster appears before source cluster.
	srcStartIdx, srcEndIdx := findClusterString(str, clusterSrcName)
	dstStartIdx, dstEndIdx := findClusterString(str, clusterDstName)
	if dstEndIdx <= srcStartIdx {
		return str[:dstStartIdx] + str[srcStartIdx:srcEndIdx] + str[dstEndIdx:srcStartIdx] + str[dstStartIdx:dstEndIdx] + str[srcEndIdx:]
	}
	return str
}

func genSubGraph(graph *cgraph.Graph, result opsv1alpha1.NodeResult, firstNodeName string, dir cgraph.DirType, addNodeNum int) []*cgraph.Node {
	var nodes []*cgraph.Node

	// Show the name of cluster.
	if len(result.Node) > 0 {
		graph.SetLabel(result.Node)
		if dir == cgraph.ForwardDir {
			graph.SetLabelJust(cgraph.LeftJust)
		} else {
			graph.SetLabelJust(cgraph.RightJust)
		}
	}

	// Construct the first node. Show it only if we know the name of it.
	node := createEndpointNodeWithDefaultStyle(graph, firstNodeName)
	nodes = append(nodes, node)
	if len(firstNodeName) > 0 {
		node.SetColor(grey)
		node.SetFillColor(lightGrey)
		node.SetStyle(cgraph.BoldNodeStyle + "," + cgraph.FilledNodeStyle)
	} else {
		node.SetStyle("invis")
	}

	// Reorder the observations according to the direction of edges.
	// Before that, deep copy observations to prevent possible risks of the original traceflow being modified.
	obs := make([]opsv1alpha1.Observation, len(result.Observations))
	copy(obs, result.Observations)
	if dir == cgraph.BackDir {
		for i := len(obs)/2 - 1; i >= 0; i-- {
			opp := len(obs) - 1 - i
			obs[i], obs[opp] = obs[opp], obs[i]
		}
	}

	// Draw the actual observations of traceflow.
	for _, o := range obs {
		// Construct node and edge.
		nodeName := fmt.Sprintf("%s_%d", graph.Name(), len(nodes))
		node := createNodeWithDefaultStyle(graph, nodeName)
		node.SetLabel(string(o.Component))
		nodes = append(nodes, node)
		if len(nodes) > 1 {
			edgeName := fmt.Sprintf("%s_%d", graph.Name(), len(nodes))
			edge := createEdgeWithDefaultStyle(graph, edgeName, nodes[len(nodes)-2], nodes[len(nodes)-1])
			edge.SetDir(dir)
			// Make the graph centered by adjusting the length of edge between the first two nodes.
			if len(nodes) == 2 {
				edge.SetMinLen(1 + addNodeNum)
			} else {
				edge.SetMinLen(1)
			}
			if o.Action == opsv1alpha1.Dropped && dir == cgraph.BackDir {
				edge.SetStyle("invis")
			}
		}
		// Set the pattern of node.
		if o.Action == opsv1alpha1.Dropped {
			node.SetColor(fireBrick)
			node.SetFillColor(mistyRose)
		} else {
			node.SetFillColor(gainsboro)
		}
		// Set the message shown inside node.
		labelStr := getTraceflowMessage(&o)
		node.SetLabel(labelStr)
	}
	return nodes
}

func GenGraph(tf *opsv1alpha1.Traceflow) string {
	g := graphviz.New()
	graph, err := g.Graph()
	if err != nil {
		log.Fatal(err)
	}
	graph.SetCenter(true)
	graph.SetLabel(tf.Name)
	graph.SetLabelLocation(cgraph.TopLocation)

	senderRst := getNodeResult(tf, isSender)
	receiverRst := getNodeResult(tf, isReceiver)
	if tf == nil || senderRst == nil || tf.Status.Phase != opsv1alpha1.Succeeded || len(senderRst.Observations) == 0 {
		return genOutput(g, graph, true)
	}

	cluster1 := createClusterWithDefaultStyle(graph, clusterSrcName)
	// Handle single node traceflow.
	if receiverRst == nil {
		nodes := genSubGraph(cluster1, *senderRst, getSrcNodeName(tf), cgraph.ForwardDir, 0)
		// Draw the destination pod and involved edge.
		edgeName := fmt.Sprintf("%s_%d", cluster1.Name(), len(senderRst.Observations))
		if len(nodes) == 0 {
			return genOutput(g, graph, true)
		}
		switch senderRst.Observations[len(senderRst.Observations)-1].Action {
		// If the last action of the sender is FORWARDED,
		// then the packet has been sent out by sender, implying that there is a disconnection.
		case opsv1alpha1.Forwarded:
			lastNode := createEndpointNodeWithDefaultStyle(graph, getDstNodeName(tf))
			edge, _ := graph.CreateEdge(edgeName, nodes[len(nodes)-1], lastNode)
			edge.SetColor(darkRed)
			edge.SetPenWidth(2.0)
			edge.SetStyle(cgraph.DashedEdgeStyle)
		case opsv1alpha1.Delivered:
			lastNode := createEndpointNodeWithDefaultStyle(cluster1, getDstNodeName(tf))
			createEdgeWithDefaultStyle(cluster1, edgeName, nodes[len(nodes)-1], lastNode)
		}
		return genOutput(g, graph, true)
	}

	// Make the graph centered by balancing the difference of node numbers on two sides with the length of first edge.
	var nodeNum int
	if len(senderRst.Observations) > len(receiverRst.Observations) {
		nodeNum = len(senderRst.Observations)
	} else {
		nodeNum = len(receiverRst.Observations)
	}

	// Draw the nodes for the sender.
	nodes1 := genSubGraph(cluster1, *senderRst, getSrcNodeName(tf), cgraph.ForwardDir, nodeNum-len(senderRst.Observations))

	// Draw the nodes for the receiver.
	cluster2 := createClusterWithDefaultStyle(graph, clusterDstName)
	nodes2 := genSubGraph(cluster2, *receiverRst, getDstNodeName(tf), cgraph.BackDir, nodeNum-len(receiverRst.Observations))

	// Draw the cross-cluster edge.
	if len(nodes1) > 0 && len(nodes2) > 0 {
		edge := createEdgeWithDefaultStyle(graph, "cross_node", nodes1[len(nodes1)-1], nodes2[len(nodes2)-1])
		edge.SetConstraint(false)
	}

	return genOutput(g, graph, false)
}
