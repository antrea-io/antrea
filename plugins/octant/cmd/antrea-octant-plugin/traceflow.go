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
	"errors"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/graphviz"
)

var (
	addTfAction         = "traceflow/addTf"
	addLiveTfAction     = "traceflow/addLiveTf"
	showGraphAction     = "traceflow/showGraphAction"
	runTraceAgainAction = "traceflow/runTraceAgain"
)

const (
	traceflowTitle         = "Traceflow Info"
	antreaTraceflowTitle   = "Antrea Traceflow"
	octantTraceflowCRDPath = "/cluster-overview/custom-resources/traceflows.crd.antrea.io/v1alpha1/"

	tfNameCol       = "Trace"
	srcNamespaceCol = "Source Namespace"
	srcPodCol       = "Source Pod"
	srcTypeCol      = "Source Type"
	srcCol          = "Source"
	srcPortCol      = "Source Port"
	dstTypeCol      = "Destination Type"
	dstNamespaceCol = "Destination Namespace"
	dstCol          = "Destination"
	dstPortCol      = "Destination Port"
	protocolCol     = "Protocol"
	phaseCol        = "Phase"
	ageCol          = "Age"
	traceNameCol    = "Trace Name"
	dropOnlyCol     = "Drop Only"
	timeoutCol      = "Timeout"

	TIME_FORMAT_YYYYMMDD_HHMMSS = "20060102-150405"
	invalidInputMsg             = "Invalid user input, CRD creation or Traceflow request may fail: "
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

// actionHandler handlers clicks and actions from "Start New Trace", "Start New Live-traffic Trace",  "Generate Trace Graph", and "Run Trace Again" buttons
func (p *antreaOctantPlugin) actionHandler(request *service.ActionRequest) error {
	actionName, err := request.Payload.String("action")
	if err != nil {
		log.Printf("Failed to get input at string: %s\n", err)
		return nil
	}
	switch actionName {
	case addTfAction:
		srcNamespace, err := checkNamespace(request)
		if err != nil {
			return nil
		}

		// Judge the destination type and get destination according to the type.
		dstType, err := checkDstType(request)
		if err != nil {
			return nil
		}
		dst, err := checkDst(request)
		if err != nil {
			return nil
		}
		dstNamespace, err := checkDstNamespace(request)
		if err != nil {
			return nil
		}

		source := crdv1alpha1.Source{}
		var sourceName string
		srcPod, err := request.Payload.String(srcPodCol)
		if err != nil {
			alertPrinter(request, invalidInputMsg+"failed to get srcPod as string",
				"Failed to get source Pod as string", nil, err)
			return nil
		}
		err = validatePodName(request, srcPod, "source")
		if err != nil {
			return nil
		}
		err = validateNamespace(request, srcNamespace, "source")
		if err != nil {
			return nil
		}
		source = crdv1alpha1.Source{
			Namespace: srcNamespace,
			Pod:       srcPod,
		}
		sourceName = srcPod

		destination, err := checkDestination(request, dst, dstType, dstNamespace, false, true)
		if err != nil {
			return nil
		}

		// It is not required for users to input port numbers and timeout
		hasSrcPort, hasDstPort, srcPort, dstPort := checkPorts(request)
		hasTimeout, timeout := checkTimeout(request)
		protocol, err := checkProtocol(request)
		if err != nil {
			return nil
		}

		tfName := sourceName + "-" + dst + "-" + time.Now().Format(TIME_FORMAT_YYYYMMDD_HHMMSS)
		tf := initTfSpec(tfName, source, destination, protocol)
		if hasTimeout {
			tf.Spec.Timeout = timeout
		}

		updateIPHeader(tf, hasSrcPort, hasDstPort, srcPort, dstPort)
		p.createTfCR(tf, request, context.Background(), tfName)
		return nil
	case addLiveTfAction:
		srcNamespace, err := checkNamespace(request)
		if err != nil {
			return nil
		}
		// Judge the destination type and get destination according to the type.
		dstType, err := checkDstType(request)
		if err != nil {
			return nil
		}
		dst, err := checkDst(request)
		if err != nil {
			return nil
		}
		dstNamespace, err := checkDstNamespace(request)
		if err != nil {
			return nil
		}
		source := crdv1alpha1.Source{}
		var sourceName string
		var srcLen int
		var isSrcPodType bool
		dstLen := len(dst)

		// Judge the source type and get source according to the type.
		srcType, err := request.Payload.StringSlice(srcTypeCol)
		if err != nil || len(srcType) == 0 {
			alertPrinter(request, invalidInputMsg+"failed to get srcType as string slice",
				"Invalid source type choice, please check your input and submit again", nil, err)
			return nil
		}
		src, err := request.Payload.String(srcCol)
		if err != nil {
			alertPrinter(request, invalidInputMsg+"failed to get src as string",
				"Failed to get source as string", nil, err)
			return nil
		}
		srcLen = len(src)
		if srcLen == 0 && dstLen == 0 {
			alertPrinter(request, invalidInputMsg+"one of source/destination must be set, and must be a Pod.",
				"One of source/destination must be set, and must be a Pod, please check your input and submit again.", nil, nil)
			return nil
		}

		if srcLen > 0 {
			switch srcType[0] {
			case "Pod":
				err := validatePodName(request, src, "source")
				if err != nil {
					return nil
				}
				err = validateNamespace(request, srcNamespace, "source")
				if err != nil {
					return nil
				}
				isSrcPodType = true
				source = crdv1alpha1.Source{
					Namespace: srcNamespace,
					Pod:       src,
				}
			case "IPv4":
				err := validateIP(request, src, "source")
				if err != nil {
					return nil
				}
				source = crdv1alpha1.Source{
					IP: src,
				}
			}
			sourceName = src
		}
		destination := crdv1alpha1.Destination{}
		if dstLen == 0 && isSrcPodType {
			goto ContinueWithoutCheckDst
		}

		destination, err = checkDestination(request, dst, dstType, dstNamespace, true, isSrcPodType)
		if err != nil {
			return nil
		}
	ContinueWithoutCheckDst:
		// It is not required for users to input port numbers.
		hasSrcPort, hasDstPort, srcPort, dstPort := checkPorts(request)
		hasTimeout, timeout := checkTimeout(request)
		protocol, err := checkProtocol(request)
		if err != nil {
			return nil
		}
		// It is not required for users to input port numbers.
		dropOnlyChecked := false
		dropOnly, err := request.Payload.StringSlice(dropOnlyCol)
		if err != nil || len(dropOnly) == 0 {
			alertPrinter(request, invalidInputMsg+"failed to get dropOnly as string slice",
				"Failed to get dropOnly as string, please check your input and submit again", nil, err)
			return nil
		}
		if dropOnly[0] == "Yes" {
			dropOnlyChecked = true
		}

		tfName := "live-"
		if srcLen == 0 {
			tfName += "dst-" + dst
		} else if dstLen == 0 {
			tfName += "src-" + sourceName
		} else {
			tfName += sourceName + "-" + dst
		}
		tfName += "-" + time.Now().Format(TIME_FORMAT_YYYYMMDD_HHMMSS)
		tf := initTfSpec(tfName, source, destination, protocol)
		tf.Spec.LiveTraffic = true
		if dropOnlyChecked {
			tf.Spec.DroppedOnly = true
		}
		if hasTimeout {
			tf.Spec.Timeout = timeout
		}

		updateIPHeader(tf, hasSrcPort, hasDstPort, srcPort, dstPort)
		p.createTfCR(tf, request, context.Background(), tfName)
		return nil
	case showGraphAction:
		traceName, err := request.Payload.StringSlice(traceNameCol)
		if err != nil || len(traceName) == 0 {
			alertPrinter(request, invalidInputMsg+"failed to get graph name as string",
				"Failed to get graph name as string", nil, err)
			return nil
		}

		name := traceName[0]
		// Invoke GenGraph to show
		ctx := context.Background()
		tf, err := p.client.CrdV1alpha1().Traceflows().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			alertPrinter(request, invalidInputMsg+"failed to get traceflow CRD "+name,
				"Failed to get traceflow CRD", nil, err)
			return nil
		}
		log.Printf("Get traceflow CRD \"%s\" successfully, Traceflow Results: %+v\n", name, tf)
		p.lastTf = tf
		p.graph, err = graphviz.GenGraph(p.lastTf)
		if err != nil {
			alertPrinter(request, "Failed to generate traceflow graph "+name, "Failed to generate traceflow graph", nil, err)
			return nil
		}
		return nil
	case runTraceAgainAction:
		// Check if traceflow has been run before
		if p.lastTf == nil {
			alert := action.CreateAlert(action.AlertTypeError,
				`Failed to run traceflow again: Use 'START NEW TRACE' or 'START NEW LIVE-TRAFFIC TRACE' to 
				run a traceflow before attempting to run a traceflow again.`,
				action.DefaultAlertExpiration)
			request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
			return nil
		}
		tf := &crdv1alpha1.Traceflow{}
		tf.Spec = p.lastTf.Spec

		// Get name of new traceflow
		temporaryRune := []rune(p.lastTf.Name)
		tf.Name = string(temporaryRune[0 : len(p.lastTf.Name)-15])
		tf.Name += time.Now().Format(TIME_FORMAT_YYYYMMDD_HHMMSS)

		p.createTfCR(tf, request, context.Background(), tf.Name)
		return nil
	default:
		log.Fatalf("Failed to find defined handler after receiving action request for %s\n", pluginName)
		return nil
	}
}

func checkNamespace(request *service.ActionRequest) (string, error) {
	srcNamespace, err := request.Payload.String(srcNamespaceCol)
	if err != nil {
		alertPrinter(request, invalidInputMsg+"failed to get srcNamespace as string",
			"Failed to get source Namespace as string", nil, err)
		return "", err
	}
	return srcNamespace, nil
}

func checkDstType(request *service.ActionRequest) (string, error) {
	dstType, err := request.Payload.StringSlice(dstTypeCol)
	if err != nil || len(dstType) == 0 {
		alertPrinter(request, invalidInputMsg+"failed to get dstType as string slice",
			"Invalid destination type choice, please check your input and submit again", nil, err)
		return "", err
	}
	return dstType[0], nil
}

func checkDst(request *service.ActionRequest) (string, error) {
	dst, err := request.Payload.String(dstCol)
	if err != nil {
		alertPrinter(request, invalidInputMsg+"failed to get dst as string",
			"Failed to get destination as string", nil, err)
		return "", err
	}
	return dst, nil
}

func checkDstNamespace(request *service.ActionRequest) (string, error) {
	dstNamespace, err := request.Payload.OptionalString(dstNamespaceCol)
	if err != nil {
		alertPrinter(request, invalidInputMsg+"failed to get dstNamespace as string",
			"Failed to get destination Namespace as string", nil, err)
		return "", err
	}
	return dstNamespace, nil
}

func checkDestination(request *service.ActionRequest, dst string, dstType string, dstNamespace string, isLiveTraffic bool, isSrcPodType bool) (crdv1alpha1.Destination, error) {
	var destination crdv1alpha1.Destination
	switch dstType {
	case crdv1alpha1.DstTypePod:
		err := validatePodName(request, dst, "destination")
		if err != nil {
			return crdv1alpha1.Destination{}, err
		}
		err = validateNamespace(request, dstNamespace, "destination")
		if err != nil {
			return crdv1alpha1.Destination{}, err
		}
		destination = crdv1alpha1.Destination{
			Namespace: dstNamespace,
			Pod:       dst,
		}
	case crdv1alpha1.DstTypeIPv4:
		if isLiveTraffic && !isSrcPodType {
			alertPrinter(request, invalidInputMsg+"one of source/destination must be a Pod: "+dst+".",
				"One of source/destination must be a Pod, please check your input and submit again.", nil, nil)
			return crdv1alpha1.Destination{}, errors.New("one of source/destination must be a Pod")
		}
		err := validateIP(request, dst, "destination")
		if err != nil {
			return crdv1alpha1.Destination{}, err
		}
		destination = crdv1alpha1.Destination{
			IP: dst,
		}
	case crdv1alpha1.DstTypeService:
		if isLiveTraffic && !isSrcPodType {
			alertPrinter(request, invalidInputMsg+"one of source/destination must be a Pod: "+dst+".",
				"One of source/destination must be a Pod, please check your input and submit again.", nil, nil)
			return crdv1alpha1.Destination{}, errors.New("one of source/destination must be a Pod")
		}
		err := validateNamespace(request, dstNamespace, "destination")
		if err != nil {
			return crdv1alpha1.Destination{}, err
		}
		if errs := validation.NameIsDNS1035Label(dst, false); len(errs) != 0 {
			alertPrinter(request, invalidInputMsg+"failed to validate destination service string: "+dst,
				"Invalid destination service string, please check your input and submit again", errs, nil)
			return crdv1alpha1.Destination{}, errors.New("invalid destination")
		}
		destination = crdv1alpha1.Destination{
			Namespace: dstNamespace,
			Service:   dst,
		}
	}
	return destination, nil

}

func checkPorts(request *service.ActionRequest) (bool, bool, uint16, uint16) {
	hasSrcPort, hasDstPort := true, true
	srcPort, err := request.Payload.Uint16(srcPortCol)
	if err != nil {
		hasSrcPort = false
	}
	dstPort, err := request.Payload.Uint16(dstPortCol)
	if err != nil {
		hasDstPort = false
	}
	return hasSrcPort, hasDstPort, srcPort, dstPort
}

func checkProtocol(request *service.ActionRequest) (string, error) {
	protocol, err := request.Payload.StringSlice(protocolCol)
	if err != nil || len(protocol) == 0 {
		alertPrinter(request, invalidInputMsg+"failed to get protocol as string slice",
			"Failed to get protocol as string, please check your input and submit again", nil, err)
		return "", err
	}
	return protocol[0], nil
}

func checkTimeout(request *service.ActionRequest) (bool, uint16) {
	hasTimeout := true
	timeout, err := request.Payload.Uint16(timeoutCol)
	if err != nil {
		hasTimeout = false
	}
	return hasTimeout, timeout
}

func updateIPHeader(tf *crdv1alpha1.Traceflow, hasSrcPort bool, hasDstPort bool, srcPort uint16, dstPort uint16) {
	switch tf.Spec.Packet.IPHeader.Protocol {
	case crdv1alpha1.TCPProtocol:
		tf.Spec.Packet.TransportHeader.TCP = &crdv1alpha1.TCPHeader{
			Flags: 2,
		}
		if hasSrcPort {
			tf.Spec.Packet.TransportHeader.TCP.SrcPort = int32(srcPort)
		}
		if hasDstPort {
			tf.Spec.Packet.TransportHeader.TCP.DstPort = int32(dstPort)
		}
	case crdv1alpha1.UDPProtocol:
		tf.Spec.Packet.TransportHeader.UDP = &crdv1alpha1.UDPHeader{}
		if hasSrcPort {
			tf.Spec.Packet.TransportHeader.UDP.SrcPort = int32(srcPort)
		}
		if hasDstPort {
			tf.Spec.Packet.TransportHeader.UDP.DstPort = int32(dstPort)
		}
	case crdv1alpha1.ICMPProtocol:
		tf.Spec.Packet.TransportHeader.ICMP = &crdv1alpha1.ICMPEchoRequestHeader{
			ID:       0,
			Sequence: 0,
		}
	}
}

func validatePodName(request *service.ActionRequest, podName string, podType string) error {
	if errs := validation.NameIsDNSSubdomain(podName, false); len(errs) != 0 {
		alertPrinter(request, invalidInputMsg+"failed to validate "+podType+" Pod string "+podName,
			"Invalid "+podType+"  Pod string, please check your input and submit again", errs, nil)
		return errors.New("invalid Pod name")
	}
	return nil
}

func validateNamespace(request *service.ActionRequest, namespace string, namespaceType string) error {
	if errs := validation.ValidateNamespaceName(namespace, false); len(errs) != 0 {
		alertPrinter(request, invalidInputMsg+"failed to validate "+namespaceType+" Namespace string "+namespace,
			"Invalid "+namespaceType+" Namespace string, please check your input and submit again", errs, nil)
		return errors.New("invalid Namespace")
	}
	return nil
}

func validateIP(request *service.ActionRequest, ipStr string, ipType string) error {
	s := net.ParseIP(ipStr)
	if s == nil {
		alertPrinter(request, invalidInputMsg+"failed to get "+ipType+" IP as a valid IPv4 IP.",
			"Invalid "+ipType+" IPv4 string, please check your input and submit again.", nil, nil)
		return errors.New("invalid IP")
	}
	if s.To4() == nil {
		alertPrinter(request, invalidInputMsg+"failed to get "+ipType+" IP as a valid IPv4 IP.",
			"Invalid "+ipType+" IPv4 string, please check your input and submit again.", nil, nil)
		return errors.New("invalid IP")
	}
	return nil
}

func initTfSpec(tfName string, source crdv1alpha1.Source, destination crdv1alpha1.Destination, protocol string) *crdv1alpha1.Traceflow {
	return &crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: tfName,
		},
		Spec: crdv1alpha1.TraceflowSpec{
			Source:      source,
			Destination: destination,
			Packet: crdv1alpha1.Packet{
				IPHeader: crdv1alpha1.IPHeader{
					Protocol: crdv1alpha1.SupportedProtocols[protocol],
				},
			},
		},
	}
}

func alertPrinter(request *service.ActionRequest, logMsg string, alertMsg string, errs []string, err error) {
	var alert action.Alert
	if len(errs) > 0 {
		log.Printf(logMsg+", err: %s\n", errs)
		alert = action.CreateAlert(action.AlertTypeError, fmt.Sprintf(alertMsg+", err: %s", errs), action.DefaultAlertExpiration)
	} else if err != nil {
		log.Printf(logMsg+", err: %#v\n", err)
		alert = action.CreateAlert(action.AlertTypeError, fmt.Sprintf(alertMsg+", err: %#v", err), action.DefaultAlertExpiration)
	} else {
		log.Println(logMsg)
		alert = action.CreateAlert(action.AlertTypeError, alertMsg, action.DefaultAlertExpiration)
	}
	request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
}

func (p *antreaOctantPlugin) createTfCR(tf *crdv1alpha1.Traceflow, request *service.ActionRequest, ctx context.Context, tfName string) {
	log.Printf("Get user input successfully, traceflow: %+v\n", tf)
	tf, err := p.client.CrdV1alpha1().Traceflows().Create(ctx, tf, metav1.CreateOptions{})
	if err != nil {
		alertPrinter(request, invalidInputMsg+"Failed to create traceflow CRD "+tfName,
			"Failed to create traceflow CRD", nil, err)
		return
	}
	log.Printf("Create traceflow CRD \"%s\" successfully, Traceflow Results: %+v\n", tfName, tf)
	alert := action.CreateAlert(action.AlertTypeSuccess, fmt.Sprintf("Traceflow \"%s\" is created successfully",
		tfName), action.DefaultAlertExpiration)
	request.DashboardClient.SendAlert(request.Context(), request.ClientID, alert)
	// Automatically delete the traceflow CRD after created for 300s(5min).
	go func(tfName string) {
		age := time.Second * 300
		time.Sleep(age)
		err := p.client.CrdV1alpha1().Traceflows().Delete(context.Background(), tfName, metav1.DeleteOptions{})
		if err != nil {
			log.Printf("Failed to delete traceflow CRD \"%s\", err: %s\n", tfName, err)
			return
		}
		log.Printf("Deleted traceflow CRD \"%s\" successfully after %.0f seconds\n", tfName, age.Seconds())
	}(tf.Name)
	p.lastTf = tf
	p.graph, err = graphviz.GenGraph(p.lastTf)
	if err != nil {
		alertPrinter(request, invalidInputMsg+"Failed to generate traceflow graph "+tfName,
			"Failed to generate traceflow graph", nil, err)
		return
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

	srcNamespaceField := component.NewFormFieldText(srcNamespaceCol+" (Not required when source is an IP)", srcNamespaceCol, "")
	srcPodField := component.NewFormFieldText(srcPodCol, srcPodCol, "")
	srcPortField := component.NewFormFieldNumber(srcPortCol, srcPortCol, "")
	dstTypeField := component.NewFormFieldSelect(dstTypeCol, dstTypeCol, dstTypeSelect, false)
	dstNamespaceField := component.NewFormFieldText(dstNamespaceCol+" (Not required when destination is an IP)", dstNamespaceCol, "")
	dstField := component.NewFormFieldText(dstCol, dstCol, "")
	dstPortField := component.NewFormFieldNumber(dstPortCol, dstPortCol, "")
	protocolField := component.NewFormFieldSelect(protocolCol, protocolCol, protocolSelect, false)

	defaultTimeout := strconv.Itoa(int(crdv1alpha1.DefaultTraceflowTimeout))
	timeoutField := component.NewFormFieldNumber(timeoutCol+" (Default value is "+defaultTimeout+" seconds)", timeoutCol, defaultTimeout)

	tfFields := []component.FormField{
		srcNamespaceField,
		srcPodField,
		srcPortField,
		dstTypeField,
		dstNamespaceField,
		dstField,
		dstPortField,
		protocolField,
		timeoutField,
		component.NewFormFieldHidden("action", addTfAction),
	}

	form := component.Form{Fields: tfFields}
	addTf := component.Action{
		Name:  "Start New Trace",
		Title: "Start New Trace",
		Form:  form,
	}

	dropOnlySelect := []component.InputChoice{
		{Label: "Yes", Value: "Yes", Checked: false},
		{Label: "No", Value: "No", Checked: true},
	}
	// only Pod and IPv4 are supported for source in live traffic trace flow
	srcTypeSelect := make([]component.InputChoice, 2)
	for i, t := range []string{"Pod", "IPv4"} {
		srcTypeSelect[i] = component.InputChoice{
			Label:   t,
			Value:   t,
			Checked: false,
		}
		// Set the default source type.
		if t == "Pod" {
			srcTypeSelect[i].Checked = true
		}
	}
	srcTypeField := component.NewFormFieldSelect(srcTypeCol, srcTypeCol, srcTypeSelect, false)
	srcField := component.NewFormFieldText(srcCol, srcCol, "")
	dropOnlyField := component.NewFormFieldSelect(dropOnlyCol+" (Only capture packets dropped by NetworkPolicies)", dropOnlyCol, dropOnlySelect, false)

	liveTfFields := []component.FormField{
		srcNamespaceField,
		srcTypeField,
		srcField,
		srcPortField,
		dstTypeField,
		dstNamespaceField,
		dstField,
		dstPortField,
		protocolField,
		timeoutField,
		dropOnlyField,
		component.NewFormFieldHidden("action", addLiveTfAction),
	}

	liveForm := component.Form{Fields: liveTfFields}
	addLiveTf := component.Action{
		Name:  "Start New Live-traffic Trace",
		Title: "Start New Live-traffic Trace",
		Form:  liveForm,
	}

	// Construct the available list of traceflow CRD.
	tfsItems := p.getSortedTfItems()
	traceflowSelect := make([]component.InputChoice, len(tfsItems))
	for i, t := range tfsItems {
		traceflowSelect[i] = component.InputChoice{
			Label:   t.Name,
			Value:   t.Name,
			Checked: false,
		}
	}
	if len(tfsItems) > 0 {
		traceflowSelect[0].Checked = true
	}

	graphForm := component.Form{Fields: []component.FormField{
		component.NewFormFieldSelect(traceNameCol, traceNameCol, traceflowSelect, false),
		component.NewFormFieldHidden("action", showGraphAction),
	}}
	genGraph := component.Action{
		Name:  "Generate Trace Graph",
		Title: "Generate Trace Graph",
		Form:  graphForm,
	}

	// Run the previous traceflow again.
	traceAgainForm := component.Form{Fields: []component.FormField{
		component.NewFormFieldHidden("action", runTraceAgainAction),
	}}
	runTraceAgain := component.Action{
		Name:  "Run Trace Again",
		Title: "Run Trace Again",
		Form:  traceAgainForm,
	}
	card.SetBody(component.NewText(""))
	card.AddAction(addTf)
	card.AddAction(addLiveTf)
	card.AddAction(genGraph)
	card.AddAction(runTraceAgain)

	graphCard := component.NewCard(component.TitleFromString("Antrea Traceflow Graph"))
	if p.lastTf.Name != "" {
		// Invoke GenGraph to show
		log.Printf("Generating content from CRD...\n")
		ctx := context.Background()
		tf, err := p.client.CrdV1alpha1().Traceflows().Get(ctx, p.lastTf.Name, metav1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get latest CRD, using traceflow results cache, last traceflow name: %s, err: %s\n", p.lastTf.Name, err)
			p.graph, err = graphviz.GenGraph(p.lastTf)
			if err != nil {
				log.Printf("Failed to generate traceflow graph \"%s\", err: %s\n", p.lastTf.Name, err)
				return component.EmptyContentResponse, nil
			}
			log.Printf("Generated content from CRD cache successfully, last traceflow name: %s\n", p.lastTf.Name)
		} else {
			p.lastTf = tf
			p.graph, err = graphviz.GenGraph(p.lastTf)
			if err != nil {
				log.Printf("Failed to generate traceflow graph \"%s\", err: %s\n", p.lastTf.Name, err)
				return component.EmptyContentResponse, nil
			}
			log.Printf("Generated content from latest CRD successfully, last traceflow name %s\n", p.lastTf.Name)
		}
		log.Printf("Traceflow Results: %+v\n", p.lastTf)
	}
	if p.graph != "" {
		graphCard.SetBody(component.NewGraphviz(p.graph))
	} else {
		graphCard.SetBody(component.NewText(""))
	}
	listSection := layout.AddSection()
	err := listSection.Add(card, component.WidthFull)
	if err != nil {
		log.Printf("Failed to add card to section: %s\n", err)
		return component.EmptyContentResponse, nil
	}
	if p.graph != "" {
		err = listSection.Add(graphCard, component.WidthFull)
		if err != nil {
			log.Printf("Failed to add graphCard to section: %s\n", err)
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
	tfsItems := p.getSortedTfItems()
	tfRows := make([]component.TableRow, 0)
	for idx := range tfsItems {
		tf := &tfsItems[idx]
		tfRows = append(tfRows, component.TableRow{
			tfNameCol:       component.NewLink(tf.Name, tf.Name, octantTraceflowCRDPath+tf.Name),
			srcNamespaceCol: component.NewText(tf.Spec.Source.Namespace),
			srcPodCol:       component.NewText(tf.Spec.Source.Pod),
			dstNamespaceCol: component.NewText(tf.Spec.Destination.Namespace),
			dstTypeCol:      component.NewText(getDstType(tf)),
			dstCol:          component.NewText(getDstName(tf)),
			protocolCol:     component.NewText(crdv1alpha1.ProtocolsToString[tf.Spec.Packet.IPHeader.Protocol]),
			phaseCol:        component.NewText(string(tf.Status.Phase)),
			ageCol:          component.NewTimestamp(tf.CreationTimestamp.Time),
		})
	}
	tfCols := component.NewTableCols(tfNameCol, srcNamespaceCol, srcPodCol, dstNamespaceCol, dstTypeCol, dstCol, protocolCol, phaseCol, ageCol)
	return component.NewTableWithRows(traceflowTitle, "We couldn't find any traceflows!", tfCols, tfRows)
}

func (p *antreaOctantPlugin) getSortedTfItems() []crdv1alpha1.Traceflow {
	ctx := context.Background()
	tfs, err := p.client.CrdV1alpha1().Traceflows().List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		log.Fatalf("Failed to get traceflows: %v\n", err)
		return nil
	}
	sort.Slice(tfs.Items, func(p, q int) bool {
		return tfs.Items[p].CreationTimestamp.Unix() > tfs.Items[q].CreationTimestamp.Unix()
	})
	return tfs.Items
}
