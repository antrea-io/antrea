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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/awalterschulze/gographviz"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	darkRed    = `"#B20000"`
	mistyRose  = `"#EDD5D5"`
	fireBrick  = `"#B22222"`
	ghostWhite = `"#F8F8FF"`
	gainsboro  = `"#DCDCDC"`
	lightGrey  = `"#C8C8C8"`
	silver     = `"#C0C0C0"`
	grey       = `"#808080"`
	dimGrey    = `"#696969"`
)

var (
	clusterSrcName = "cluster_source"
	clusterDstName = "cluster_destination"
)

// createDirectedEdgeWithDefaultStyle creates a node with default style (usually used to represent a component in traceflow) .
func createNodeWithDefaultStyle(graph *gographviz.Graph, parentGraph string, name string) (*gographviz.Node, error) {
	err := graph.AddNode(parentGraph, name, map[string]string{
		"shape": "box",
		"style": `"rounded,filled,solid"`,
		"color": dimGrey,
	})
	if err != nil {
		return nil, err
	}
	return graph.Nodes.Lookup[name], nil
}

// createEndpointNodeWithDefaultStyle creates an endpoint node with default style.
// EndpointNode is the the type of node for endpoints in networks like the sender and the receiver.
func createEndpointNodeWithDefaultStyle(graph *gographviz.Graph, parentGraph string, name string) (*gographviz.Node, error) {
	err := graph.AddNode(parentGraph, name, map[string]string{
		"style":     `"filled,bold"`,
		"color":     grey,
		"fillcolor": lightGrey,
	})
	if err != nil {
		return nil, err
	}
	return graph.Nodes.Lookup[name], nil
}

// createDirectedEdgeWithDefaultStyle creates a directed edge with default style.
// It is allowed to create duplicate edges.
func createDirectedEdgeWithDefaultStyle(graph *gographviz.Graph, start *gographviz.Node, end *gographviz.Node, isForwardDir bool) (*gographviz.Edge, error) {
	err := graph.AddEdge(start.Name, end.Name, true, map[string]string{
		"penwidth": "2.0",
		"color":    silver,
	})
	if err != nil {
		return nil, err
	}
	edges := graph.Edges.SrcToDsts[start.Name][end.Name]
	if len(edges) == 0 {
		return nil, errors.New(fmt.Sprintf("Failed to create a new edge between node %s and node %s", start.Name, end.Name))
	}
	edge := edges[len(edges)-1]
	if isForwardDir {
		edge.Attrs[gographviz.Dir] = "forward"
	} else {
		edge.Attrs[gographviz.Dir] = "back"
	}
	return edge, nil
}

// createDirectedEdgeWithDefaultStyle creates a cluster with default style.
// In Graphviz, cluster is a subgraph which is surrounded by a rectangle and the nodes belonging to the cluster are drawn together.
// In traceflow, a cluster is usually used to represent a K8s node.
func createClusterWithDefaultStyle(graph *gographviz.Graph, name string) (*gographviz.SubGraph, error) {
	err := graph.AddSubGraph(graph.Name, name, map[string]string{
		"style":   `"filled,bold"`,
		"bgcolor": ghostWhite,
	})
	if err != nil {
		return nil, err
	}
	return graph.SubGraphs.SubGraphs[name], nil
}

func isSender(result *crdv1alpha1.NodeResult) bool {
	if len(result.Observations) == 0 {
		return false
	}
	if result.Observations[0].Component != crdv1alpha1.ComponentSpoofGuard || result.Observations[0].Action != crdv1alpha1.ActionForwarded {
		return false
	}
	return true
}

func isReceiver(result *crdv1alpha1.NodeResult) bool {
	if len(result.Observations) == 0 {
		return false
	}
	if result.Observations[0].Component != crdv1alpha1.ComponentForwarding || result.Observations[0].Action != crdv1alpha1.ActionReceived {
		return false
	}
	return true
}

// In DOT language, some symbols are used to parse the Graphviz DOT language, including but not limited to ",", "/", "#", etc.
// All Graphviz attributes are specified by name-value pairs. If the value string contains such symbols, we need to add a pair
// of quotation marks to prevent them from being used for parsing the DOT language.
// More details about DOT language can be seen at: https://graphviz.org/doc/info/lang.html.
func getWrappedStr(str string) string {
	// In quoted strings in DOT, the only escaped character is double-quote (").
	// That is, in quoted strings, the dyad \" is converted to "; all other characters are left unchanged.
	wStr := strings.ReplaceAll(str, `"`, `\"`)
	return `"` + wStr + `"`
}

func getNodeResult(tf *crdv1alpha1.Traceflow, fn func(result *crdv1alpha1.NodeResult) bool) *crdv1alpha1.NodeResult {
	for i := range tf.Status.Results {
		result := tf.Status.Results[i]
		if fn(&result) {
			return &result
		}
	}
	return nil
}

func getSrcNodeName(tf *crdv1alpha1.Traceflow) string {
	if len(tf.Spec.Source.Namespace) > 0 && len(tf.Spec.Source.Pod) > 0 {
		return getWrappedStr(tf.Spec.Source.Namespace + "/" + tf.Spec.Source.Pod)
	}
	return ""
}

func getDstNodeName(tf *crdv1alpha1.Traceflow) string {
	if len(tf.Spec.Destination.Namespace) > 0 && len(tf.Spec.Destination.Service) > 0 {
		return getWrappedStr(tf.Spec.Destination.Namespace + "/" + tf.Spec.Destination.Pod +
			"\nService: " + tf.Spec.Destination.Service)
	}
	if len(tf.Spec.Destination.IP) > 0 {
		return getWrappedStr(tf.Spec.Destination.IP)
	}
	if len(tf.Spec.Destination.Namespace) > 0 && len(tf.Spec.Destination.Pod) > 0 {
		return getWrappedStr(tf.Spec.Destination.Namespace + "/" + tf.Spec.Destination.Pod)
	}
	return ""
}

// getTraceflowMessage gets the shown message string in traceflow graph.
func getTraceflowMessage(o *crdv1alpha1.Observation, spec *crdv1alpha1.TraceflowSpec) string {
	str := string(o.Component)
	if len(o.ComponentInfo) > 0 {
		str += "\n" + o.ComponentInfo
	}
	str += "\n" + string(o.Action)
	if o.Component == crdv1alpha1.ComponentNetworkPolicy && len(o.NetworkPolicy) > 0 {
		str += "\nNetpol: " + o.NetworkPolicy
	}
	if len(o.Pod) > 0 {
		str += "\nTo: " + o.Pod
		if len(spec.Destination.Pod) == 0 {
			spec.Destination.Pod = o.Pod[strings.Index(o.Pod, `/`)+1:]
		}
	}
	if o.Action != crdv1alpha1.ActionDropped && len(o.TranslatedDstIP) > 0 {
		str += "\nTranslated Destination IP: " + o.TranslatedDstIP
	}
	if o.Action != crdv1alpha1.ActionDropped && len(o.TunnelDstIP) > 0 {
		str += "\nTunnel Destination IP : " + o.TunnelDstIP
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

func genOutput(graph *gographviz.Graph, isSingleCluster bool) string {
	str := graph.String()
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

func getTraceflowStatusMessage(tf *crdv1alpha1.Traceflow) string {
	switch tf.Status.Phase {
	case crdv1alpha1.Failed:
		return getWrappedStr(fmt.Sprintf("Traceflow %s failed: %s", tf.Name, tf.Status.Reason))
	case crdv1alpha1.Running:
		return getWrappedStr(fmt.Sprintf("Traceflow %s is running...", tf.Name))
	case crdv1alpha1.Pending:
		return getWrappedStr(fmt.Sprintf("Traceflow %s is pending...", tf.Name))
	default:
		return getWrappedStr("Unknown Traceflow status. Please check whether Antrea is running.")
	}
}

func genSubGraph(graph *gographviz.Graph, cluster *gographviz.SubGraph, result *crdv1alpha1.NodeResult, spec *crdv1alpha1.TraceflowSpec,
	endpointNodeName string, isForwardDir bool, addNodeNum int) ([]*gographviz.Node, error) {
	var nodes []*gographviz.Node

	// Show the name of cluster.
	if len(result.Node) > 0 {
		cluster.Attrs[gographviz.Label] = getWrappedStr(result.Node)
		if isForwardDir {
			cluster.Attrs[gographviz.LabelJust] = "l"
		} else {
			cluster.Attrs[gographviz.LabelJust] = "r"
		}
	}

	// Construct the first node. Show it only if we know the name of it.
	node, err := createEndpointNodeWithDefaultStyle(graph, cluster.Name, endpointNodeName)
	if err != nil {
		return nil, err
	}
	nodes = append(nodes, node)
	if len(endpointNodeName) == 0 {
		node.Attrs[gographviz.Style] = `"invis"`
	}

	// Reorder the observations according to the direction of edges.
	// Before that, deep copy observations to prevent possible risks of the original traceflow being modified.
	obs := make([]crdv1alpha1.Observation, len(result.Observations))
	copy(obs, result.Observations)
	if !isForwardDir {
		for i := len(obs)/2 - 1; i >= 0; i-- {
			opp := len(obs) - 1 - i
			obs[i], obs[opp] = obs[opp], obs[i]
		}
	}

	// Draw the actual observations of traceflow.
	for i := range obs {
		o := obs[i]
		// Construct node and edge.
		nodeName := fmt.Sprintf("%s_%d", cluster.Name, len(nodes))
		node, err := createNodeWithDefaultStyle(graph, cluster.Name, nodeName)
		if err != nil {
			return nil, err
		}
		node.Attrs[gographviz.Label] = getWrappedStr(string(o.Component))
		nodes = append(nodes, node)
		if len(nodes) > 1 {
			edge, err := createDirectedEdgeWithDefaultStyle(graph, nodes[len(nodes)-2], nodes[len(nodes)-1], isForwardDir)
			if err != nil {
				return nil, err
			}
			// Make the graph centered by adjusting the length of edge between the first two nodes.
			if len(nodes) == 2 {
				edge.Attrs[gographviz.MinLen] = strconv.Itoa(1 + addNodeNum)
			} else {
				edge.Attrs[gographviz.MinLen] = "1"
			}
			if o.Action == crdv1alpha1.ActionDropped && !isForwardDir {
				edge.Attrs[gographviz.Style] = `"invis"`
			}
		}
		// Set the pattern of node.
		if o.Action == crdv1alpha1.ActionDropped {
			node.Attrs[gographviz.Color] = fireBrick
			node.Attrs[gographviz.FillColor] = mistyRose
		} else {
			node.Attrs[gographviz.FillColor] = gainsboro
		}
		// Set the message shown inside node.
		labelStr := getTraceflowMessage(&o, spec)
		node.Attrs[gographviz.Label] = getWrappedStr(labelStr)
	}
	return nodes, nil
}

func GenGraph(tf *crdv1alpha1.Traceflow) (string, error) {
	g, _ := gographviz.ParseString(`digraph G {}`)
	graph := gographviz.NewGraph()
	if err := gographviz.Analyse(g, graph); err != nil {
		return "", err
	}
	graph.Attrs[gographviz.Center] = "true"
	graph.Attrs[gographviz.Label] = getWrappedStr(tf.Name)
	graph.Attrs[gographviz.LabelLOC] = "t"
	err := graph.SetDir(true)
	if err != nil {
		return "", err
	}

	senderRst := getNodeResult(tf, isSender)
	receiverRst := getNodeResult(tf, isReceiver)
	if tf.Status.Phase != crdv1alpha1.Succeeded {
		graph.Attrs[gographviz.Label] = getTraceflowStatusMessage(tf)
	}
	if tf == nil || senderRst == nil || tf.Status.Phase != crdv1alpha1.Succeeded || len(senderRst.Observations) == 0 {
		return genOutput(graph, true), nil
	}

	cluster1, err := createClusterWithDefaultStyle(graph, clusterSrcName)
	if err != nil {
		return "", err
	}
	// Handle single node traceflow.
	if receiverRst == nil {
		nodes, err := genSubGraph(graph, cluster1, senderRst, &tf.Spec, getSrcNodeName(tf), true, 0)
		if err != nil {
			return "", err
		}
		// Draw the destination pod and involved edge.
		if len(nodes) == 0 {
			return genOutput(graph, true), nil
		}
		switch senderRst.Observations[len(senderRst.Observations)-1].Action {
		// If the last action of the sender is FORWARDED,
		// then the packet has been sent out by sender, implying that there is a disconnection.
		case crdv1alpha1.ActionForwarded:
			lastNode, err := createEndpointNodeWithDefaultStyle(graph, graph.Name, getDstNodeName(tf))
			if err != nil {
				return "", err
			}
			err = graph.AddEdge(nodes[len(nodes)-1].Name, lastNode.Name, true, map[string]string{
				"penwidth": "2.0",
				"color":    darkRed,
				"style":    `"dashed"`,
			})
			if err != nil {
				return "", err
			}
		case crdv1alpha1.ActionDelivered:
			lastNode, err := createEndpointNodeWithDefaultStyle(graph, cluster1.Name, getDstNodeName(tf))
			if err != nil {
				return "", err
			}
			_, err = createDirectedEdgeWithDefaultStyle(graph, nodes[len(nodes)-1], lastNode, true)
			if err != nil {
				return "", err
			}
		}
		return genOutput(graph, true), nil
	}

	// Make the graph centered by balancing the difference of node numbers on two sides with the length of first edge.
	var nodeNum int
	if len(senderRst.Observations) > len(receiverRst.Observations) {
		nodeNum = len(senderRst.Observations)
	} else {
		nodeNum = len(receiverRst.Observations)
	}

	// Draw the nodes for the sender.
	nodes1, err := genSubGraph(graph, cluster1, senderRst, &tf.Spec, getSrcNodeName(tf), true, nodeNum-len(senderRst.Observations))
	if err != nil {
		return "", err
	}

	// Draw the nodes for the receiver.
	cluster2, err := createClusterWithDefaultStyle(graph, clusterDstName)
	if err != nil {
		return "", err
	}
	nodes2, err := genSubGraph(graph, cluster2, receiverRst, &tf.Spec, getDstNodeName(tf), false, nodeNum-len(receiverRst.Observations))
	if err != nil {
		return "", err
	}

	// Draw the cross-cluster edge.
	if len(nodes1) > 0 && len(nodes2) > 0 {
		edge, err := createDirectedEdgeWithDefaultStyle(graph, nodes1[len(nodes1)-1], nodes2[len(nodes2)-1], true)
		if err != nil {
			return "", err
		}
		edge.Attrs[gographviz.Constraint] = "false"
	}

	return genOutput(graph, false), nil
}
