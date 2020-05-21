package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"github.com/vmware-tanzu/octant/pkg/view/flexlayout"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vmware-tanzu/antrea/plugins/pkg/apis/traceflow/v1"
	clientset "github.com/vmware-tanzu/antrea/plugins/pkg/client/clientset/versioned"
	"github.com/vmware-tanzu/antrea/plugins/pkg/graphviz"
)

var (
	pluginName                           = "traceflowPlugin"
	addTfAction                          = "traceflowPlugin/addTf"
	showGraphAction                      = "traceflowPlugin/showGraphAction"
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
	dstSvcCol       = "Destination Service"
	dstPortCol      = "Destination Port"
	protocolCol     = "Protocol"
	crdCol          = "Detailed Information"
	phaseCol        = "Phase"
)

// This is octant-trace-plugin.
// The plugin needs to run with octant version v0.10.2 or later.
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

	p, err := service.Register(pluginName, "a description", capabilities, options...)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("octant-traceflow-plugin is starting")
	p.Serve()
}

type traceflowPlugin struct {
	client *clientset.Clientset
	graph  string
}

func newTraceflowPlugin() *traceflowPlugin {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv(kubeConfig))
	if err != nil {
		log.Fatalf("Failed to build kubeConfig %v", err)
	}
	client, err = clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client for antrea-traceflow-octant-plugin %v", err)
	}
	return &traceflowPlugin{
		client: client,
		graph:  "",
	}
}

func (a *traceflowPlugin) navHandler(request *service.NavigationRequest) (navigation.Navigation, error) {
	return navigation.Navigation{
		Title:    "Trace Flow",
		Path:     request.GeneratePath("components"),
		IconName: "cloud",
	}, nil
}

func (a *traceflowPlugin) actionHandler(request *service.ActionRequest) error {
	actionName, err := request.Payload.String("action")
	if err != nil {
		log.Printf("unable to get input at string: %w", err)
		return nil
	}

	switch actionName {
	case addTfAction:
		srcNamespace, err := request.Payload.String(srcNamespaceCol)
		if err != nil {
			log.Printf("unable to get srcNamespace at string : %w", err)
		}
		srcPod, err := request.Payload.String(srcPodCol)
		if err != nil {
			log.Printf("unable to get srcPod at string : %w", err)
		}
		srcPort, err := request.Payload.String(srcPortCol)
		if err != nil {
			log.Printf("unable to get srcPort at string : %w", err)
		}
		dstNamespace, err := request.Payload.String(dstNamespaceCol)
		if err != nil {
			log.Printf("unable to get dstNamespace at string : %w", err)
		}
		dstPod, err := request.Payload.String(dstPodCol)
		if err != nil {
			log.Printf("unable to get dstPod at string : %w", err)
		}
		dstService, err := request.Payload.String(dstSvcCol)
		if err != nil {
			log.Printf("unable to get dstService at string : %w", err)
		}
		dstPort, err := request.Payload.String(dstPortCol)
		if err != nil {
			log.Printf("unable to get dstPort at string : %w", err)
		}
		protocol, err := request.Payload.String(protocolCol)
		if err != nil {
			log.Printf("unable to get dstPod at string : %w", err)
		}
		tf := &v1.Traceflow{
			ObjectMeta: metav1.ObjectMeta{
				Name: srcPod + "." + dstPod,
			},
			Source: v1.Source{
				SrcNamespace: srcNamespace,
				SrcPod:       srcPod,
			},
			Destination: v1.Destination{
				DstNamespace: dstNamespace,
				DstPod:       dstPod,
				DstService:   dstService,
			},
			RoundID: "",
			Packet:  v1.Packet{},
			Status:  v1.Status{},
		}
		if srcPort != "" {
			sport, err := strconv.Atoi(srcPort)
			if err == nil {
				tf.TCPHeader.SrcTCPPort = int32(sport)
			}
		}
		if dstPort != "" {
			dport, err := strconv.Atoi(dstPort)
			if err == nil {
				tf.TCPHeader.DstTCPPort = int32(dport)
			}
		}
		if protocol == "TCP" {
			tf.Protocol = 6
		}
		tf, err = a.client.AntreaV1().Traceflows().Create(tf)
		if err != nil {
			log.Printf("Failed to create tf %v", err)
			return err
		}
		a.graph = graphviz.GenGraph(tf)
		return nil
	case showGraphAction:
		name, err := request.Payload.String("name")
		if err != nil {
			return fmt.Errorf("unable to get name at string : %w", err)
		}
		// Invoke GenGraph to show
		tf, err := a.client.AntreaV1().Traceflows().Get(name, metav1.GetOptions{})
		if err != nil {
			return nil
		}
		a.graph = graphviz.GenGraph(tf)
		return nil
	default:
		return fmt.Errorf("recieved action request for %s, but no handler defined", pluginName)
	}
}

func (a *traceflowPlugin) initRoutes(router *service.Router) {
	router.HandleFunc("/components", a.traceflowHandler)
}

func (a *traceflowPlugin) traceflowHandler(request *service.Request) (component.ContentResponse, error) {
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
	if a.graph != "" {
		graphCard.SetBody(component.NewGraphviz(a.graph))
	} else {
		graphCard.SetBody(component.NewText(""))
	}
	listSection := layout.AddSection()
	err := listSection.Add(card, component.WidthFull)
	if err != nil {
		return component.ContentResponse{}, fmt.Errorf("error adding card to section: %w", err)
	}
	if a.graph != "" {
		err = listSection.Add(graphCard, component.WidthFull)
		if err != nil {
			return component.ContentResponse{}, fmt.Errorf("error adding graphCard to section: %w", err)
		}
	}

	tfCols := component.NewTableCols(tfNameCol, srcNamespaceCol, srcPodCol, dstNamespaceCol, dstPodCol, crdCol, phaseCol)
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
	tfs, err := client.AntreaV1().Traceflows().List(metav1.ListOptions{})
	if err != nil {
		log.Fatalf("Failed to get Traceflows %v", err)
	}
	tfRows := make([]component.TableRow, 0)
	for _, tf := range tfs.Items {
		tfRows = append(tfRows, component.TableRow{
			tfNameCol:       component.NewText(tf.Name),
			srcNamespaceCol: component.NewText(tf.SrcNamespace),
			srcPodCol:       component.NewText(tf.SrcPod),
			dstNamespaceCol: component.NewText(tf.DstNamespace),
			dstPodCol:       component.NewText(tf.DstPod),
			crdCol: component.NewLink(tf.Name, tf.Name,
				"/cluster-overview/custom-resources/traceflows.antrea.tanzu.vmware.com/v1/"+tf.Name),
			phaseCol: component.NewText(string(tf.Phase)),
		})
	}
	return tfRows
}
