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
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/vmware-tanzu/octant/pkg/action"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"github.com/vmware-tanzu/octant/pkg/view/flexlayout"
	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/graphviz"
)

var (
	addTfAction     = "traceflow/addTf"
	showGraphAction = "traceflow/showGraphAction"
)

const (
	traceflowTitle         = "Traceflow Info"
	antreaTraceflowTitle   = "Antrea Traceflow"
	octantTraceflowCRDPath = "/cluster-overview/custom-resources/traceflows.crd.antrea.io/v1alpha1/"

	tfNameCol       = "Trace"
	srcNamespaceCol = "Source Namespace"
	srcPodCol       = "Source Pod"
	srcPortCol      = "Source Port"
	dstTypeCol      = "Destination Type"
	dstNamespaceCol = "Destination Namespace"
	dstCol          = "Destination"
	dstPortCol      = "Destination Port"
	protocolCol     = "Protocol"
	phaseCol        = "Phase"
	ageCol          = "Age"
	traceNameCol    = "Trace Name"

	TIME_FORMAT_YYYYMMDD_HHMMSS = "20060102-150405"
)

// getDstName gets the name of destination for specific traceflow.
func getDstName(tf *crdv1alpha1.Traceflow) string {
	if len(tf.Spec.Destination.Pod) > 0 {
		return tf.Spec.Destination.Pod
	}
	if len(tf.Spec.Destination.Service) > 0 {
		return tf.Spec.Destination.Service
	}
	if len(tf.Spec.Destination.IP) > 0 {
		return tf.Spec.Destination.IP
	}
	return ""
}

// getDstType gets the type of destination for specific traceflow.
func getDstType(tf *crdv1alpha1.Traceflow) string {
	if len(tf.Spec.Destination.Pod) > 0 {
		return crdv1alpha1.DstTypePod
	}
	if len(tf.Spec.Destination.Service) > 0 {
		return crdv1alpha1.DstTypeService
	}
	if len(tf.Spec.Destination.IP) > 0 {
		return crdv1alpha1.DstTypeIPv4
	}
	return ""
}

// actionHandler handlers clicks and actions from "Start New Trace" and "Generate Trace Graph" buttons.
func (p *antreaOctantPlugin) actionHandler(request *service.ActionRequest) error {
	actionName, err := request.Payload.String("action")
	if err != nil {
		log.Printf("Failed to get input at string: %s", err)
		return nil
	}

	switch actionName {
	case addTfAction:
		srcNamespace, err := request.Payload.String(srcNamespaceCol)
		if err != nil {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to get srcNamespace as string: %s", err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to get source namespace as "+
				"string: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		if errs := validation.ValidateNamespaceName(srcNamespace, false); len(errs) != 0 {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to validate source namespace string %s, errs: %#v", srcNamespace, errs)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid source namespace string, "+
				"please check your input and submit again."), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}

		srcPod, err := request.Payload.String(srcPodCol)
		if err != nil {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to get srcPod as string: %s", err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to get source pod as "+
				"string: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		if errs := validation.NameIsDNSSubdomain(srcPod, false); len(errs) != 0 {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to validate source pod string %s, errs: %#v", srcPod, errs)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid source pod string, "+
				"please check your input and submit again."), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}

		// Judge the destination type and get destination according to the type.
		dstType, err := request.Payload.StringSlice(dstTypeCol)
		if err != nil || len(dstType) == 0 {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to get dstType as string slice: %s", err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid destination type choice, "+
				"please check your input and submit again."), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		dst, err := request.Payload.String(dstCol)
		if err != nil {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to get dst as string: %s", err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to get destination as "+
				"string: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		dstNamespace, err := request.Payload.OptionalString(dstNamespaceCol)
		if err != nil {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to get dstNamespace as string: %s", err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to get destination namespace as "+
				"string: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		var destination crdv1alpha1.Destination
		switch dstType[0] {
		case crdv1alpha1.DstTypePod:
			if errs := validation.NameIsDNSSubdomain(dst, false); len(errs) != 0 {
				log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
					"failed to validate destination pod string %s, errs: %#v", dst, errs)
				alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid destination pod string, "+
					"please check your input and submit again."), action.DefaultAlertExpiration)
				request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
				return nil
			}
			if errs := validation.ValidateNamespaceName(dstNamespace, false); len(errs) != 0 {
				log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
					"failed to validate destination namespace string %s, errs: %#v", dstNamespace, errs)
				alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid destination namespace string, "+
					"please check your input and submit again."), action.DefaultAlertExpiration)
				request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
				return nil
			}
			destination = crdv1alpha1.Destination{
				Namespace: dstNamespace,
				Pod:       dst,
			}
		case crdv1alpha1.DstTypeIPv4:
			s := net.ParseIP(dst)
			if s == nil {
				log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
					"failed to get destination IP as a valid IPv4 IP: %s", err)
				alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid destination IPv4 string, "+
					"please check your input and submit again."), action.DefaultAlertExpiration)
				request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
				return nil
			}
			if s.To4() == nil {
				log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
					"failed to get destination IP as a valid IPv4 IP: %s", err)
				alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid destination IPv4 string, "+
					"please check your input and submit again."), action.DefaultAlertExpiration)
				request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
				return nil
			}
			destination = crdv1alpha1.Destination{
				IP: dst,
			}
		case crdv1alpha1.DstTypeService:
			if errs := validation.ValidateNamespaceName(dstNamespace, false); len(errs) != 0 {
				log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
					"failed to validate destination namespace string %s, errs: %#v", dstNamespace, errs)
				alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid destination namespace string, "+
					"please check your input and submit again."), action.DefaultAlertExpiration)
				request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
				return nil
			}
			if errs := validation.NameIsDNS1035Label(dst, false); len(errs) != 0 {
				log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
					"failed to validate destination service string %s, errs: %#v", dst, errs)
				alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Invalid destination service string, "+
					"please check your input and submit again."), action.DefaultAlertExpiration)
				request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
				return nil
			}
			destination = crdv1alpha1.Destination{
				Namespace: dstNamespace,
				Service:   dst,
			}
		}

		// It is not required for users to input port numbers.
		hasSrcPort, hasDstPort := true, true
		srcPort, err := request.Payload.Uint16(srcPortCol)
		if err != nil {
			hasSrcPort = false
		}
		dstPort, err := request.Payload.Uint16(dstPortCol)
		if err != nil {
			hasDstPort = false
		}

		protocol, err := request.Payload.StringSlice(protocolCol)
		if err != nil || len(protocol) == 0 {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"failed to get protocol as string slice: %s", err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to get protocol as "+
				"string: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}

		// Judge whether the name of trace flow is duplicated.
		// If it is, then the user creates more than one traceflows in one second, which is not allowed.
		tfName := srcPod + "-" + dst + "-" + time.Now().Format(TIME_FORMAT_YYYYMMDD_HHMMSS)
		ctx := context.Background()
		tfOld, _ := p.client.CrdV1alpha1().Traceflows().Get(ctx, tfName, v1.GetOptions{})
		if tfOld.Name == tfName {
			log.Printf("Invalid user input, CRD creation or Traceflow request may fail: "+
				"duplicate traceflow \"%s\": same source pod and destination pod in less than one second: %+v. ", tfName, tfOld)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Duplicate traceflow: same source pod "+
				"and destination pod in less than one second"), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}

		tf := &crdv1alpha1.Traceflow{
			ObjectMeta: v1.ObjectMeta{
				Name: tfName,
			},
			Spec: crdv1alpha1.TraceflowSpec{
				Source: crdv1alpha1.Source{
					Namespace: srcNamespace,
					Pod:       srcPod,
				},
				Destination: destination,
				Packet: crdv1alpha1.Packet{
					IPHeader: crdv1alpha1.IPHeader{
						Protocol: crdv1alpha1.SupportedProtocols[protocol[0]],
					},
				},
			},
		}

		switch tf.Spec.Packet.IPHeader.Protocol {
		case crdv1alpha1.TCPProtocol:
			{
				tf.Spec.Packet.TransportHeader.TCP = &crdv1alpha1.TCPHeader{
					Flags: 2,
				}
				if hasSrcPort {
					tf.Spec.Packet.TransportHeader.TCP.SrcPort = int32(srcPort)
				}
				if hasDstPort {
					tf.Spec.Packet.TransportHeader.TCP.DstPort = int32(dstPort)
				}
			}
		case crdv1alpha1.UDPProtocol:
			{
				tf.Spec.Packet.TransportHeader.UDP = &crdv1alpha1.UDPHeader{}
				if hasSrcPort {
					tf.Spec.Packet.TransportHeader.UDP.SrcPort = int32(srcPort)
				}
				if hasDstPort {
					tf.Spec.Packet.TransportHeader.UDP.DstPort = int32(dstPort)
				}
			}
		case crdv1alpha1.ICMPProtocol:
			{
				tf.Spec.Packet.TransportHeader.ICMP = &crdv1alpha1.ICMPEchoRequestHeader{
					ID:       0,
					Sequence: 0,
				}
			}
		}
		log.Printf("Get user input successfully, traceflow: %+v", tf)
		tf, err = p.client.CrdV1alpha1().Traceflows().Create(ctx, tf, v1.CreateOptions{})
		if err != nil {
			log.Printf("Failed to create traceflow CRD \"%s\", err: %s", tfName, err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to create traceflow CRD, "+
				"err: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		log.Printf("Create traceflow CRD \"%s\" successfully, Traceflow Results: %+v", tfName, tf)
		alert := action.CreateAlert(action.AlertTypeSuccess, fmt.Sprintf("Traceflow \"%s\" is created successfully",
			tfName), action.DefaultAlertExpiration)
		request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
		// Automatically delete the traceflow CRD after created for 300s(5min).
		go func(tfName string) {
			age := time.Second * 300
			time.Sleep(age)
			err := p.client.CrdV1alpha1().Traceflows().Delete(context.Background(), tfName, v1.DeleteOptions{})
			if err != nil {
				log.Printf("Failed to delete traceflow CRD \"%s\", err: %s", tfName, err)
				return
			}
			log.Printf("Deleted traceflow CRD \"%s\" successfully after %.0f seconds", tfName, age.Seconds())
		}(tf.Name)
		p.lastTf = tf
		p.graph, err = graphviz.GenGraph(p.lastTf)
		if err != nil {
			log.Printf("Failed to generate traceflow graph \"%s\", err: %s", tfName, err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to generate traceflow graph, "+
				"err: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		return nil
	case showGraphAction:
		name, err := request.Payload.String(traceNameCol)
		if err != nil {
			log.Printf("Failed to get name at string: %s", err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to get graph name as "+
				"string: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		// Invoke GenGraph to show
		ctx := context.Background()
		tf, err := p.client.CrdV1alpha1().Traceflows().Get(ctx, name, v1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get traceflow CRD \"%s\", err: %s ", name, err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to get traceflow CRD, "+
				"err: %s ", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		log.Printf("Get traceflow CRD \"%s\" successfully, Traceflow Results: %+v", name, tf)
		p.lastTf = tf
		p.graph, err = graphviz.GenGraph(p.lastTf)
		if err != nil {
			log.Printf("Failed to generate traceflow graph \"%s\", err: %s", name, err)
			alert := action.CreateAlert(action.AlertTypeError, fmt.Sprintf("Failed to generate traceflow graph, "+
				"err: %s", err), action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		return nil
	default:
		log.Fatalf("Failed to find defined handler after receiving action request for %s", pluginName)
		return nil
	}
}

// traceflowHandler handlers the layout of Traceflow page.
func (p *antreaOctantPlugin) traceflowHandler(request service.Request) (component.ContentResponse, error) {
	layout := flexlayout.New()
	card := component.NewCard(component.TitleFromString(antreaTraceflowTitle))

	// Construct the available values of destination types.
	dstTypeSelect := make([]component.InputChoice, len(crdv1alpha1.SupportedDestinationTypes))
	for i, t := range crdv1alpha1.SupportedDestinationTypes {
		dstTypeSelect[i] = component.InputChoice{
			Label:   t,
			Value:   t,
			Checked: false,
		}
		// Set the default destination type.
		if t == crdv1alpha1.DstTypePod {
			dstTypeSelect[i].Checked = true
		}
	}

	// Construct the available values of protocols.
	protocolSelect := make([]component.InputChoice, len(crdv1alpha1.SupportedProtocols))
	i := 0
	for p := range crdv1alpha1.SupportedProtocols {
		protocolSelect[i] = component.InputChoice{
			Label:   p,
			Value:   p,
			Checked: false,
		}
		// Set the default protocol.
		if p == "TCP" {
			protocolSelect[i].Checked = true
		}
		i++
	}

	form := component.Form{Fields: []component.FormField{
		component.NewFormFieldText(srcNamespaceCol, srcNamespaceCol, ""),
		component.NewFormFieldText(srcPodCol, srcPodCol, ""),
		component.NewFormFieldNumber(srcPortCol, srcPortCol, ""),
		component.NewFormFieldSelect(dstTypeCol, dstTypeCol, dstTypeSelect, false),
		component.NewFormFieldText(dstNamespaceCol+" (Not required when destination is an IP)", dstNamespaceCol, ""),
		component.NewFormFieldText(dstCol, dstCol, ""),
		component.NewFormFieldNumber(dstPortCol, dstPortCol, ""),
		component.NewFormFieldSelect(protocolCol, protocolCol, protocolSelect, false),
		component.NewFormFieldHidden("action", addTfAction),
	}}
	addTf := component.Action{
		Name:  "Start New Trace",
		Title: "Start New Trace",
		Form:  form,
	}
	graphForm := component.Form{Fields: []component.FormField{
		component.NewFormFieldText(traceNameCol, traceNameCol, ""),
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
	if p.lastTf.Name != "" {
		// Invoke GenGraph to show
		log.Printf("Generating content from CRD...")
		ctx := context.Background()
		tf, err := p.client.CrdV1alpha1().Traceflows().Get(ctx, p.lastTf.Name, v1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get latest CRD, using traceflow results cache, last traceflow name: %s, err: %s", p.lastTf.Name, err)
			p.graph, err = graphviz.GenGraph(p.lastTf)
			if err != nil {
				log.Printf("Failed to generate traceflow graph \"%s\", err: %s", p.lastTf.Name, err)
				return component.EmptyContentResponse, nil
			}
			log.Printf("Generated content from CRD cache successfully, last traceflow name: %s", p.lastTf.Name)
		} else {
			p.lastTf = tf
			p.graph, err = graphviz.GenGraph(p.lastTf)
			if err != nil {
				log.Printf("Failed to generate traceflow graph \"%s\", err: %s", p.lastTf.Name, err)
				return component.EmptyContentResponse, nil
			}
			log.Printf("Generated content from latest CRD successfully, last traceflow name %s", p.lastTf.Name)
		}
		log.Printf("Traceflow Results: %+v", p.lastTf)
	}
	if p.graph != "" {
		graphCard.SetBody(component.NewGraphviz(p.graph))
	} else {
		graphCard.SetBody(component.NewText(""))
	}
	listSection := layout.AddSection()
	err := listSection.Add(card, component.WidthFull)
	if err != nil {
		log.Printf("Failed to add card to section: %s", err)
		return component.EmptyContentResponse, nil
	}
	if p.graph != "" {
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
			p.getTfTable(request),
		},
	}
	// Setting the accessor ensures that the page shows the first tab when clicked.
	for i, c := range resp.Components {
		c.SetAccessor(resp.Title[0].String() + strconv.Itoa(i))
	}
	return resp, nil
}

// getTfTable gets the table for displaying Traceflow information
func (p *antreaOctantPlugin) getTfTable(request service.Request) *component.Table {
	ctx := context.Background()
	tfs, err := p.client.CrdV1alpha1().Traceflows().List(ctx, v1.ListOptions{ResourceVersion: "0"})
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
			dstTypeCol:      component.NewText(getDstType(&tf)),
			dstCol:          component.NewText(getDstName(&tf)),
			protocolCol:     component.NewText(crdv1alpha1.ProtocolsToString[tf.Spec.Packet.IPHeader.Protocol]),
			phaseCol:        component.NewText(string(tf.Status.Phase)),
			ageCol:          component.NewTimestamp(tf.CreationTimestamp.Time),
		})
	}
	tfCols := component.NewTableCols(tfNameCol, srcNamespaceCol, srcPodCol, dstNamespaceCol, dstTypeCol, dstCol, protocolCol, phaseCol, ageCol)
	return component.NewTableWithRows(traceflowTitle, "We couldn't find any traceflows!", tfCols, tfRows)
}
