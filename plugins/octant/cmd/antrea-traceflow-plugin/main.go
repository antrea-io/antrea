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
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"github.com/vmware-tanzu/octant/pkg/view/flexlayout"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	"github.com/vmware-tanzu/antrea/pkg/graphviz"
)

var (
	pluginName                           = "antreaTraceflowPlugin"
	addTfAction                          = pluginName + "/addTf"
	showGraphAction                      = pluginName + "/showGraphAction"
	client          *clientset.Clientset = nil
	kubeConfig                           = "KUBECONFIG"
)

const (
	tfNameCol       = "Trace"
	srcNamespaceCol = "Source Namespace"
	srcPodCol       = "Source Pod"
	srcPortCol      = "Source Port"
	dstNamespaceCol = "Destination Namespace"
	dstPodCol       = "Destination Pod"
	dstPortCol      = "Destination Port"
	protocolCol     = "Protocol"
	crdCol          = "Detailed Information"
	phaseCol        = "Phase"
	ageCol          = "Age"

	octantTraceflowCRDPath = "/cluster-overview/custom-resources/traceflows.ops.antrea.tanzu.vmware.com/v1alpha1/"

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

// This is antrea-traceflow-plugin.
func main() {
	localPlugin := newTraceflowPlugin()

	// Remove the prefix from the go logger since Octant will print logs with timestamps.
	log.SetPrefix("")

	capabilities := &plugin.Capabilities{
		ActionNames: []string{addTfAction, showGraphAction},
		IsModule:    true,
	}

	// Set up what should happen when Octant calls this plugin.
	options := []service.PluginOption{
		service.WithActionHandler(localPlugin.actionHandler),
		service.WithNavigation(localPlugin.navHandler, localPlugin.initRoutes),
	}

	p, err := service.Register(pluginName, "A plugin that starts Antrea Traceflow sessions to trace packets "+
		"in the Antrea network and draws graphs for the result packet flows.", capabilities, options...)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf(pluginName + " is starting")
	p.Serve()
}

type traceflowPlugin struct {
	client     *clientset.Clientset
	graph      string
	lastTfName string
}

func newTraceflowPlugin() *traceflowPlugin {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv(kubeConfig))
	if err != nil {
		log.Fatalf("Failed to build kubeConfig %v", err)
	}
	client, err = clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client for %s: %v", pluginName, err)
	}
	return &traceflowPlugin{
		client:     client,
		graph:      "",
		lastTfName: "",
	}
}

func (a *traceflowPlugin) navHandler(request *service.NavigationRequest) (navigation.Navigation, error) {
	return navigation.Navigation{
		Title:    "Trace Flow",
		Path:     request.GeneratePath("components"),
		IconName: "cloud",
	}, nil
}

func (a *traceflowPlugin) regExpMatch(pattern, str string) bool {
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

func (a *traceflowPlugin) actionHandler(request *service.ActionRequest) error {
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
		if match := a.regExpMatch(namespaceStrPattern, srcNamespace); !match {
			return nil
		}

		srcPod, err := request.Payload.String(srcPodCol)
		if err != nil {
			log.Printf("Failed to get srcPod at string : %s", err)
		}
		if match := a.regExpMatch(podStrPattern, srcPod); !match {
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
		if match := a.regExpMatch(namespaceStrPattern, dstNamespace); !match {
			return nil
		}

		dstPod, err := request.Payload.String(dstPodCol)
		if err != nil {
			log.Printf("Failed to get dstPod at string : %s", err)
		}
		if match := a.regExpMatch(podStrPattern, dstPod); !match {
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
		tfOld, err := a.client.OpsV1alpha1().Traceflows().Get(ctx, tfName, metav1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get traceflow \"%s\", detailed error: %s", tfName, err)
		}
		if tfOld.Name == tfName {
			log.Printf("Duplicate traceflow \"%s\": same source pod and destination pod in less than one second"+
				": %+v. ", tfName, tfOld)
			return nil
		}

		tf := &opsv1alpha1.Traceflow{
			ObjectMeta: metav1.ObjectMeta{
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
		tf, err = a.client.OpsV1alpha1().Traceflows().Create(ctx, tf, metav1.CreateOptions{})
		if err != nil {
			log.Printf("Failed to create traceflow CRD \"%s\", err: %s", tfName, err)
			return nil
		}
		log.Printf("Create traceflow CRD \"%s\" successfully, Traceflow Results: %+v", tfName, tf)
		a.lastTfName = tf.Name
		a.graph = graphviz.GenGraph(tf)
		return nil
	case showGraphAction:
		name, err := request.Payload.String("name")
		if err != nil {
			log.Printf("Failed to get name at string : %w", err)
			return nil
		}
		// Invoke GenGraph to show
		ctx := context.Background()
		tf, err := a.client.OpsV1alpha1().Traceflows().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			log.Printf("Failed to get traceflow CRD \"%s\", err: %s ", name, err)
			return nil
		}
		log.Printf("Get traceflow CRD \"%s\" successfully, Traceflow Results: %+v", name, tf)
		a.lastTfName = tf.Name
		a.graph = graphviz.GenGraph(tf)
		return nil
	default:
		log.Fatalf("Failed to find defined handler after receiving action request for %s", pluginName)
		return nil
	}
}

func (a *traceflowPlugin) initRoutes(router *service.Router) {
	router.HandleFunc("/components", a.traceflowHandler)
}

func (a *traceflowPlugin) traceflowHandler(request service.Request) (component.ContentResponse, error) {
	layout := flexlayout.New()
	card := component.NewCard(component.TitleFromString("Antrea Traceflow"))
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
	if a.lastTfName != "" {
		// Invoke GenGraph to show
		log.Printf("Generating content from CRD...")
		ctx := context.Background()
		tf, err := a.client.OpsV1alpha1().Traceflows().Get(ctx, a.lastTfName, metav1.GetOptions{})
		if err != nil {
			log.Printf("Failed to generate content from CRD, lastTfName %v, err: %s", a.lastTfName, err)
			return component.ContentResponse{}, nil
		}
		log.Printf("Traceflow Results: %+v", tf)
		a.graph = graphviz.GenGraph(tf)
		log.Printf("Generated content from CRD successfully, lastTfName %v", a.lastTfName)
	}
	if a.graph != "" {
		graphCard.SetBody(component.NewGraphviz(a.graph))
	} else {
		graphCard.SetBody(component.NewText(""))
	}
	listSection := layout.AddSection()
	err := listSection.Add(card, component.WidthFull)
	if err != nil {
		log.Printf("Failed to add card to section: %s", err)
		return component.ContentResponse{}, nil
	}
	if a.graph != "" {
		err = listSection.Add(graphCard, component.WidthFull)
		if err != nil {
			log.Printf("Failed to add graphCard to section: %s", err)
			return component.ContentResponse{}, nil
		}
	}

	tfCols := component.NewTableCols(tfNameCol, srcNamespaceCol, srcPodCol, dstNamespaceCol, dstPodCol, crdCol, phaseCol, ageCol)
	tfTable := component.NewTableWithRows("Trace List", "", tfCols, a.getTfRows())
	return component.ContentResponse{
		Title: component.TitleFromString("Antrea Traceflow"),
		Components: []component.Component{
			layout.ToComponent("Antrea Traceflow"),
			tfTable,
		},
	}, nil
}

// getTfRows gets rows for displaying Controller information
func (a *traceflowPlugin) getTfRows() []component.TableRow {
	ctx := context.Background()
	tfs, err := client.OpsV1alpha1().Traceflows().List(ctx, metav1.ListOptions{})
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
			tfNameCol:       component.NewText(tf.Name),
			srcNamespaceCol: component.NewText(tf.Spec.Source.Namespace),
			srcPodCol:       component.NewText(tf.Spec.Source.Pod),
			dstNamespaceCol: component.NewText(tf.Spec.Destination.Namespace),
			dstPodCol:       component.NewText(tf.Spec.Destination.Pod),
			crdCol:          component.NewLink(tf.Name, tf.Name, octantTraceflowCRDPath+tf.Name),
			phaseCol:        component.NewText(string(tf.Status.Phase)),
			ageCol:          component.NewTimestamp(tf.CreationTimestamp.Time),
		})
	}
	return tfRows
}
