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
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
)

var (
	pluginName = "antrea-octant-plugin"
)

const (
	title = "Antrea"
)

type antreaOctantPlugin struct {
	client *clientset.Clientset
	// tfMutex protects the Traceflow state in case of multiple client
	// sessions concurrently accessing the Traceflow functionality of the
	// Antrea plugin.
	tfMutex sync.Mutex
	graph   string
	lastTf  *crdv1alpha1.Traceflow
}

func newAntreaOctantPlugin() *antreaOctantPlugin {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}
	// Create a k8s client.
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Failed to build kubeConfig %v", err)
	}
	client, err := clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client for %s: %v", pluginName, err)
	}

	return &antreaOctantPlugin{
		client: client,
		graph:  "",
		lastTf: &crdv1alpha1.Traceflow{
			ObjectMeta: v1.ObjectMeta{Name: ""},
		},
	}
}

func main() {
	// Remove the prefix from the go logger since Octant will print logs with timestamps.
	log.SetPrefix("")
	a := newAntreaOctantPlugin()

	capabilities := &plugin.Capabilities{
		ActionNames: []string{addTfAction, addLiveTfAction, showGraphAction, runTraceAgainAction},
		IsModule:    true,
	}

	// Set up navigation services
	options := []service.PluginOption{
		service.WithNavigation(a.handleNavigation, a.initRoutes),
		service.WithActionHandler(a.actionHandler),
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
func (p *antreaOctantPlugin) handleNavigation(request *service.NavigationRequest) (navigation.Navigation, error) {
	return navigation.Navigation{
		Title: title,
		Path:  request.GeneratePath(),
		Children: []navigation.Navigation{
			{
				Title:    "Overview",
				Path:     request.GeneratePath("components/overview"),
				IconName: "folder",
			},
			{
				Title:    "Controller Info",
				Path:     request.GeneratePath("components/controller"),
				IconName: "folder",
			},
			{
				Title:    "Agent Info",
				Path:     request.GeneratePath("components/agent"),
				IconName: "folder",
			},
			{
				Title:    "Traceflow",
				Path:     request.GeneratePath("components/traceflow"),
				IconName: "folder",
			},
		},
		IconName: "cloud",
	}, nil
}

// initRoutes routes for Antrea plugin.
func (p *antreaOctantPlugin) initRoutes(router *service.Router) {
	// Click on the plugin icon or navigation child named Overview to display all Antrea information.
	router.HandleFunc("", p.overviewHandler)
	router.HandleFunc("/components/overview", p.overviewHandler)

	// Click on navigation child named Controller Info to display Controller information.
	router.HandleFunc("/components/controller", p.controllerHandler)

	// Click on navigation child named Agent Info to display Agent information.
	router.HandleFunc("/components/agent", p.agentHandler)

	// Click on navigation child named "Antrea Traceflow"/"Tracelist" to display Antrea Traceflow information.
	router.HandleFunc("/components/traceflow", p.traceflowHandler)
}
