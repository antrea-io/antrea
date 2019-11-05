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
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/mux"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

// CommandBundle organizes commands apply them to a router or a server.
type CommandBundle struct {
	CommandOptions []CommandOption
	GroupVersion   *schema.GroupVersion
	Codec          serializer.CodecFactory
}

// APIPrefix returns the API prefix of the CLI service according to the GroupVersion.
func (b *CommandBundle) APIPrefix() string {
	return path.Join("/apis", b.GroupVersion.Group, b.GroupVersion.Version)
}

// ApplyToRouter applies the CommandBundle to a router.
func (b *CommandBundle) ApplyToRouter(r *mux.PathRecorderMux, aq monitor.AgentQuerier, cq monitor.ControllerQuerier) {
	for _, cmdOpt := range b.CommandOptions {
		reqPath := path.Join(b.APIPrefix(), strings.ToLower(cmdOpt.Use))
		klog.Infof("Adding cli handler %s", reqPath)
		handler := cmdOpt.HandlerFactory.Handler(aq, cq)
		r.HandleFunc(reqPath, handler)
	}
	// Set up the discovery handler.
	r.HandleFunc(b.APIPrefix(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		l := v1.APIResourceList{
			TypeMeta:     v1.TypeMeta{Kind: "APIResourceList", APIVersion: v1.SchemeGroupVersion.Version},
			GroupVersion: b.GroupVersion.String(),
		}
		if err := json.NewEncoder(w).Encode(l); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

// ApplyToClient applies the CommandBundle to the CLI client.
func (b *CommandBundle) ApplyToClient(c *Client) {
	c.GroupVersion = b.GroupVersion
	c.Codec = b.Codec
}

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

// ApplyToCommand applies the CommandBundle to the root cobra command, it applies each CommandOption of it to the root
// command as a sub-command.
func (b *CommandBundle) ApplyToCommand(root *cobra.Command, client *Client, isAgent bool) {
	for i := range b.CommandOptions { // apply sub-commands to root
		cmdOpt := b.CommandOptions[i]
		if (cmdOpt.Agent != isAgent) && (cmdOpt.Controller == isAgent) {
			continue
		}
		subCMD := new(cobra.Command)
		cmdOpt.CommandGroup.Command(root).AddCommand(subCMD)
		cmdOpt.ApplyToCommand(subCMD, client)
		renderDescription(subCMD, isAgent)
	}
	b.applyToRootCommand(root, isAgent)
}

func (b *CommandBundle) applyToRootCommand(root *cobra.Command, isAgent bool) {
	defaultPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	root.PersistentFlags().BoolP("debug", "d", false, "enable debug mode")
	root.PersistentFlags().StringP("kubeconfig", "k", defaultPath, "absolute path to the kubeconfig file")
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		enableDebug, _ := root.PersistentFlags().GetBool("debug")
		flag.Set("logtostderr", fmt.Sprint(enableDebug))
		flag.Set("alsologtostderr", fmt.Sprint(enableDebug))
		if enableDebug {
			flag.Set("v", "0")
		}
	}
	renderDescription(root, isAgent)
}

// ApplyToAPIServer applies the antctl server router to the api server.
func (b *CommandBundle) ApplyToAPIServer(server *server.GenericAPIServer, cq monitor.ControllerQuerier) {
	b.ApplyToRouter(server.Handler.NonGoRestfulMux, nil, cq)
}

// Validate if the CommandBundle is correct.
func (b *CommandBundle) Validate() []error {
	var errs []error

	if len(b.CommandOptions) == 0 { // must has at least one command
		return []error{fmt.Errorf("no command in command bundle")}
	}

	for i, c := range b.CommandOptions { // each CommandOption must be valid
		for _, err := range c.Validate() {
			errs = append(errs, errors.Wrap(err, fmt.Sprintf("#%d command<%s> :", i, c.Use)))
		}
	}

	return errs
}
