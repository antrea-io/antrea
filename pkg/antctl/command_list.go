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

package antctl

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

// commandList organizes definitions.
// It is the protocol for a pair of antctl client and server.
type commandList struct {
	definitions []commandDefinition
	codec       serializer.CodecFactory
}

func (cl *commandList) InstallToAPIServer(apiServer *server.GenericAPIServer, cq monitor.ControllerQuerier) {
	cl.applyToMux(apiServer.Handler.NonGoRestfulMux, nil, cq)
}

// applyToMux adds the handler function of each commandDefinition in the
// commandList to the mux with path /apis/<group_version>/<cmd>. It also adds
// corresponding discovery handlers at /apis/<group_version> for kubernetes service
// discovery.
func (cl *commandList) applyToMux(mux *mux.PathRecorderMux, aq monitor.AgentQuerier, cq monitor.ControllerQuerier) {
	resources := map[string][]metav1.APIResource{}
	for _, def := range cl.definitions {
		if def.HandlerFactory == nil {
			continue
		}
		handler := def.HandlerFactory.Handler(aq, cq)
		groupPath := "/apis/" + def.GroupVersion.String()
		reqPath := def.requestPath(groupPath)
		klog.Infof("Adding cli handler %s", reqPath)
		mux.HandleFunc(reqPath, handler)
		resources[groupPath] = append(resources[groupPath], metav1.APIResource{
			Name:         def.Use,
			SingularName: def.Use,
			Kind:         def.Use,
			Namespaced:   false,
			Group:        def.GroupVersion.Group,
			Version:      def.GroupVersion.Version,
			Verbs:        metav1.Verbs{"get"},
		})
	}
	// Setup up discovery handlers for command handlers.
	for groupPath, resource := range resources {
		mux.HandleFunc(groupPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			l := metav1.APIResourceList{
				TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: metav1.SchemeGroupVersion.Version},
				GroupVersion: systemGroup.Version,
				APIResources: resource,
			}
			jsonResp, err := json.MarshalIndent(l, "", "  ")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, err = w.Write(jsonResp)
			if err != nil {
				klog.Errorf("Error when responding APIResourceList: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		})
	}
}

func (cl *commandList) applyFlagsToRootCommand(root *cobra.Command) {
	defaultKubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	root.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")
	root.PersistentFlags().StringP("kubeconfig", "k", defaultKubeconfig, "absolute path to the kubeconfig file")
	root.PersistentFlags().DurationP("timeout", "t", 0, "time limit of the execution of the command")
}

// ApplyToRootCommand applies the commandList to the root cobra command, it applies
// each commandDefinition of it to the root command as a sub-command.
func (cl *commandList) ApplyToRootCommand(root *cobra.Command, isAgent bool, inPod bool) {
	client := &client{
		inPod: inPod,
		codec: cl.codec,
	}
	for _, groupCommand := range groupCommands {
		root.AddCommand(groupCommand)
	}
	for i := range cl.definitions {
		def := cl.definitions[i]
		if (def.Agent != isAgent) && (def.Controller != !isAgent) {
			continue
		}
		def.applySubCommandToRoot(root, client, isAgent)
		klog.Infof("Added command %s", def.Use)
	}
	cl.applyFlagsToRootCommand(root)
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		enableVerbose, err := root.PersistentFlags().GetBool("verbose")
		if err != nil {
			return err
		}
		err = flag.Set("logtostderr", fmt.Sprint(enableVerbose))
		if err != nil {
			return err
		}
		if enableVerbose {
			err := flag.Set("v", fmt.Sprint(math.MaxInt32))
			if err != nil {
				return err
			}
		}
		return nil
	}
	renderDescription(root, isAgent)
}

// validate checks the validation of the commandList.
func (cl *commandList) validate() []error {
	var errs []error
	if len(cl.definitions) == 0 {
		return []error{fmt.Errorf("no command found in the command list")}
	}
	for i, c := range cl.definitions {
		for _, err := range c.validate() {
			errs = append(errs, fmt.Errorf("#%d command<%s>: %w", i, c.Use, err))
		}
	}
	return errs
}

// renderDescription replaces placeholders ${component} in Short and Long of a command
// to the determined component during runtime.
func renderDescription(command *cobra.Command, isAgent bool) {
	var componentName string
	if isAgent {
		componentName = "agent"
	} else {
		componentName = "controller"
	}
	command.Short = strings.ReplaceAll(command.Short, "${component}", componentName)
	command.Long = strings.ReplaceAll(command.Long, "${component}", componentName)
}
