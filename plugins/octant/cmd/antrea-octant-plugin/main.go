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
	"sync"

	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	title      = "Antrea"
	pluginName = "antrea-octant-plugin"
)

var (
	logger = service.NewLoggerHelper()
)

type antreaOctantPlugin struct {
	// tfmutex protects the Traceflow state in case of multiple client
	// sessions concurrently accessing the Traceflow functionality of the
	// Antrea plugin.
	tfMutex sync.Mutex
	graph   string
	lastTf  *crdv1alpha1.Traceflow
}

func newAntreaOctantPlugin() *antreaOctantPlugin {
	return &antreaOctantPlugin{
		graph: "",
		lastTf: &crdv1alpha1.Traceflow{
			ObjectMeta: metav1.ObjectMeta{Name: ""},
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

	// TODO: at the moment it seems that plugin logging is buggy, so this is
	// the only use of the logger in our plugin so far.
	// When it is fixed, we should replace all usage of the Go standard
	// library log with this logger for easier debugging.
	// See https://github.com/vmware-tanzu/octant/issues/3012
	logger.Info("antrea-octant-plugin is starting")
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
