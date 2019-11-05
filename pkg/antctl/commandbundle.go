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

// ApplyToRouter applies the CommandBundle to a mux.Router. It also sets up a dummy kubernetes discovery handler.
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
		json.NewEncoder(w).Encode(l)
	})
}

// ApplyToClient applies the CommandBundle to the CLI client.
func (b *CommandBundle) ApplyToClient(c *Client, isAgent bool, isController bool) error {
	c.GroupVersion = b.GroupVersion
	c.Codec = b.Codec
	return nil
}

// ApplyToCommand applies the CommandBundle to the root cobra command, it applies each CommandOption of it to the root
// command as a sub-command.
func (b *CommandBundle) ApplyToCommand(root *cobra.Command, client *Client, isAgent, isController bool) error {
	for i := range b.CommandOptions {
		cmdOpt := b.CommandOptions[i]
		// Skip not support commands.
		if (cmdOpt.Agent != isAgent) && (cmdOpt.Controller != isController) {
			continue
		}

		klog.Infof("Adding command %s", cmdOpt.Use)
		subCMD := new(cobra.Command)
		cmdOpt.CommandGroup.Command(root).AddCommand(subCMD)

		err := cmdOpt.ApplyToCommand(subCMD, client)
		if err != nil {
			klog.Infof("Apply command %s failed: %v", cmdOpt.Use, err)
			return err
		}
	}

	defaultPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	root.PersistentFlags().StringP("kubeconfig", "c", defaultPath, "Absolute path to the kubeconfig file")
	root.PersistentFlags().StringP("master", "m", "", "Kubernetes master node address")

	return nil
}

// Validate if the CommandBundle is correct.
func (b *CommandBundle) Validate() []error {
	var errs []error

	if len(b.CommandOptions) == 0 { // must has at least one command
		return []error{fmt.Errorf("no command in command bundle")}
	}

	for i, c := range b.CommandOptions { // each CommandOption of it must be valid
		for _, err := range c.Validate() {
			errs = append(errs, errors.Wrap(err, fmt.Sprintf("#%d command<%s> :", i, c.Use)))
		}
	}

	return errs
}
