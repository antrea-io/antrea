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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"github.com/vmware-tanzu/octant/pkg/view/flexlayout"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/graphviz"
)

var (
	addTfAction     = "traceflow/addTf"
	showGraphAction = "traceflow/showGraphAction"
)

const (
	traceflowTitle         = "Traceflow Info"
	antreaTraceflowTitle   = "Antrea Traceflow"
	octantTraceflowCRDPath = "/cluster-overview/custom-resources/traceflows.ops.antrea.tanzu.vmware.com/v1alpha1/"

	tfNameCol       = "Trace"
	srcNamespaceCol = "Source Namespace"
	srcPodCol       = "Source Pod"
	srcPortCol      = "Source Port"
	dstNamespaceCol = "Destination Namespace"
	dstPodCol       = "Destination Pod"
	dstPortCol      = "Destination Port"
	protocolCol     = "Protocol"
	phaseCol        = "Phase"
	ageCol          = "Age"

	namespaceStrPattern = `[a-z0-9]([-a-z0-9]*[a-z0-9])?`
	podStrPattern       = `[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*`

	TIME_FORMAT_YYYYMMDD_HHMMSS = "20060102-150405"
)

// According to code in Antrea agent and controller, default protocol is ICMP if protocol is not inputted by users.
const (
	ICMPProtocol int32 = 1
	TCPProtocol  int32 = 6
	UDPProtocol  int32 = 17
)

var supportedProtocols = map[string]int32{
	"ICMP": ICMPProtocol,
	"TCP":  TCPProtocol,
	"UDP":  UDPProtocol,
}

func regExpMatch(pattern, str string) bool {
	match, err := regexp.MatchString(pattern, str)
	if err != nil {
		log.Printf("Failed to judge srcPod string pattern: %s", err)
		return false
	}
	if !match {
		log.Printf("Failed to match string %s and regExp pattern %s", str, pattern)
		return false
	}
	return true
}

// actionHandler handlers clicks and actions from "Start New Trace" and "Generate Trace Graph" buttons.
func actionHandler(request *service.ActionRequest) error {
	actionName, err := request.Payload.String("action")
	if err != nil {
		log.Printf("Failed to get input at string: %s", err)
		return nil
	}

	switch actionName {
	case addTfAction:
		srcNamespace, err := request.Payload.String(srcNamespaceCol)
		if err != nil {
			log.Printf("Failed to get srcNamespace at string : %s", err)
		}
		if match := regExpMatch(namespaceStrPattern, srcNamespace); !match {
			return nil
		}

		srcPod, err := request.Payload.String(srcPodCol)
		if err != nil {
			log.Printf("Failed to get srcPod at string : %s", err)
		}
		if match := regExpMatch(podStrPattern, srcPod); !match {
			return nil
		}

		srcPort, err := request.Payload.String(srcPortCol)
		if err != nil {
			log.Printf("Failed to get srcPort at string : %s", err)
		}

		dstNamespace, err := request.Payload.String(dstNamespaceCol)
		if err != nil {
			log.Printf("Failed to get dstNamespace at string : %s", err)
		}
		if match := regExpMatch(namespaceStrPattern, dstNamespace); !match {
			return nil
		}

		dstPod, err := request.Payload.String(dstPodCol)
		if err != nil {
			log.Printf("Failed to get dstPod at string : %s", err)
		}
		if match := regExpMatch(podStrPattern, dstPod); !match {
			return nil
		}

		dstPort, err := request.Payload.String(dstPortCol)
		if err != nil {
			log.Printf("Failed to get dstPort at string : %s", err)
		}

		protocol, err := request.Payload.String(protocolCol)
		if err != nil {
			log.Printf("Failed to get dstPod at string : %s", err)
		}
		protocol = strings.ToUpper(protocol)

		// Judge whether the name of trace flow is duplicated.
		// If it is, then the user creates more than one traceflows in one second, which is not allowed.
		tfName := srcPod + "-" + dstPod + "-" + time.Now().Format(TIME_FORMAT_YYYYMMDD_HHMMSS)
		ctx := context.Background()
		tfOld, err := client.OpsV1alpha1().Traceflows().Get(ctx, tfName, v1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get traceflow \"%s\", detailed error: %s", tfName, err)
		}
		if tfOld.Name == tfName {
			log.Printf("Duplicate traceflow \"%s\": same source pod and destination pod in less than one second"+
				": %+v. ", tfName, tfOld)
			return nil
		}

		tf := &opsv1alpha1.Traceflow{
			ObjectMeta: v1.ObjectMeta{
				Name: tfName,
			},
			Spec: opsv1alpha1.TraceflowSpec{
				Source: opsv1alpha1.Source{
					Namespace: srcNamespace,
					Pod:       srcPod,
				},
				Destination: opsv1alpha1.Destination{
					Namespace: dstNamespace,
					Pod:       dstPod,
				},
				Packet: opsv1alpha1.Packet{
					IPHeader: opsv1alpha1.IPHeader{
						Protocol: supportedProtocols[protocol],
					},
				},
			},
		}
		var sport, dport int
		if srcPort != "" {
			sport, err = strconv.Atoi(srcPort)
			if err != nil {
				log.Printf("Failed to get source port: %s", err)
				return nil
			}
		}
		if dstPort != "" {
			dport, err = strconv.Atoi(dstPort)
			if err != nil {
				log.Printf("Failed to get destination port: %s", err)
				return nil
			}
		}
		switch tf.Spec.Packet.IPHeader.Protocol {
		case TCPProtocol:
			{
				tf.Spec.Packet.TransportHeader.TCP = &opsv1alpha1.TCPHeader{
					SrcPort: int32(sport),
					DstPort: int32(dport),
				}
			}
		case UDPProtocol:
			{
				tf.Spec.Packet.TransportHeader.UDP = &opsv1alpha1.UDPHeader{
					SrcPort: int32(sport),
					DstPort: int32(dport),
				}
			}
		case ICMPProtocol:
			{
				tf.Spec.Packet.TransportHeader.ICMP = &opsv1alpha1.ICMPEchoRequestHeader{
					ID:       0,
					Sequence: 0,
				}
			}
		}
		tf, err = client.OpsV1alpha1().Traceflows().Create(ctx, tf, v1.CreateOptions{})
		if err != nil {
			log.Printf("Failed to create traceflow CRD \"%s\", err: %s", tfName, err)
			return nil
		}
		log.Printf("Create traceflow CRD \"%s\" successfully, Traceflow Results: %+v", tfName, tf)
		lastTf = *tf
		graph = graphviz.GenGraph(&lastTf)
		return nil
	case showGraphAction:
		name, err := request.Payload.String("name")
		if err != nil {
			log.Printf("Failed to get name at string : %w", err)
			return nil
		}
		// Invoke GenGraph to show
		ctx := context.Background()
		tf, err := client.OpsV1alpha1().Traceflows().Get(ctx, name, v1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get traceflow CRD \"%s\", err: %s ", name, err)
			return nil
		}
		log.Printf("Get traceflow CRD \"%s\" successfully, Traceflow Results: %+v", name, tf)
		lastTf = *tf
		graph = graphviz.GenGraph(&lastTf)
		return nil
	default:
		log.Fatalf("Failed to find defined handler after receiving action request for %s", pluginName)
		return nil
	}
}

// traceflowHandler handlers the layout of Traceflow page.
func traceflowHandler(request service.Request) (component.ContentResponse, error) {
	layout := flexlayout.New()
	card := component.NewCard(component.TitleFromString(antreaTraceflowTitle))
	form := component.Form{Fields: []component.FormField{
		component.NewFormFieldText(srcNamespaceCol, srcNamespaceCol, ""),
		component.NewFormFieldText(srcPodCol, srcPodCol, ""),
		component.NewFormFieldText(srcPortCol, srcPortCol, ""),
		component.NewFormFieldText(dstNamespaceCol, dstNamespaceCol, ""),
		component.NewFormFieldText(dstPodCol, dstPodCol, ""),
		component.NewFormFieldText(dstPortCol, dstPortCol, ""),
		component.NewFormFieldText(protocolCol, protocolCol, ""),
		component.NewFormFieldHidden("action", addTfAction),
	}}
	addTf := component.Action{
		Name:  "Start New Trace",
		Title: "Start New Trace",
		Form:  form,
	}
	graphForm := component.Form{Fields: []component.FormField{
		component.NewFormFieldText("name", "name", ""),
		component.NewFormFieldHidden("action", showGraphAction),
	}}
	genGraph := component.Action{
		Name:  "Generate Trace Graph",
		Title: "Generate Trace Graph",
		Form:  graphForm,
	}
	card.SetBody(component.NewText(""))
	card.AddAction(addTf)
	card.AddAction(genGraph)

	graphCard := component.NewCard(component.TitleFromString("Antrea Traceflow Graph"))
	if lastTf.Name != "" {
		// Invoke GenGraph to show
		log.Printf("Generating content from CRD...")
		ctx := context.Background()
		tf, err := client.OpsV1alpha1().Traceflows().Get(ctx, lastTf.Name, v1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get latest CRD, using traceflow results cache, last traceflow name: %s, err: %s", lastTf.Name, err)
			graph = graphviz.GenGraph(&lastTf)
			log.Printf("Generated content from CRD cache successfully, last traceflow name: %s", lastTf.Name)
		} else {
			lastTf = *tf
			graph = graphviz.GenGraph(&lastTf)
			log.Printf("Generated content from latest CRD successfully, last traceflow name %s", lastTf.Name)
		}
		log.Printf("Traceflow Results: %+v", lastTf)
	}
	if graph != "" {
		graphCard.SetBody(component.NewGraphviz(graph))
	} else {
		graphCard.SetBody(component.NewText(""))
	}
	listSection := layout.AddSection()
	err := listSection.Add(card, component.WidthFull)
	if err != nil {
		log.Printf("Failed to add card to section: %s", err)
		return component.EmptyContentResponse, nil
	}
	if graph != "" {
		err = listSection.Add(graphCard, component.WidthFull)
		if err != nil {
			log.Printf("Failed to add graphCard to section: %s", err)
			return component.EmptyContentResponse, nil
		}
	}

	resp := component.ContentResponse{
		Title: component.TitleFromString(antreaTraceflowTitle),
		Components: []component.Component{
			layout.ToComponent(antreaTraceflowTitle),
			getTfTable(request),
		},
	}
	// Setting the accessor ensures that the page shows the first tab when clicked.
	for i, c := range resp.Components {
		c.SetAccessor(resp.Title[0].String() + strconv.Itoa(i))
	}
	return resp, nil
}

// getTfTable gets the table for displaying Traceflow information
func getTfTable(request service.Request) *component.Table {
	ctx := context.Background()
	tfs, err := client.OpsV1alpha1().Traceflows().List(ctx, v1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		log.Fatalf("Failed to get Traceflows %v", err)
		return nil
	}
	sort.Slice(tfs.Items, func(p, q int) bool {
		return tfs.Items[p].CreationTimestamp.Unix() > tfs.Items[q].CreationTimestamp.Unix()
	})
	tfRows := make([]component.TableRow, 0)
	for _, tf := range tfs.Items {
		tfRows = append(tfRows, component.TableRow{
			tfNameCol:       component.NewLink(tf.Name, tf.Name, octantTraceflowCRDPath+tf.Name),
			srcNamespaceCol: component.NewText(tf.Spec.Source.Namespace),
			srcPodCol:       component.NewText(tf.Spec.Source.Pod),
			dstNamespaceCol: component.NewText(tf.Spec.Destination.Namespace),
			dstPodCol:       component.NewText(tf.Spec.Destination.Pod),
			phaseCol:        component.NewText(string(tf.Status.Phase)),
			ageCol:          component.NewTimestamp(tf.CreationTimestamp.Time),
		})
	}
	tfCols := component.NewTableCols(tfNameCol, srcNamespaceCol, srcPodCol, dstNamespaceCol, dstPodCol, phaseCol, ageCol)
	return component.NewTableWithRows(traceflowTitle, "We couldn't find any traceflows!", tfCols, tfRows)
}
