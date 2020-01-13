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
	"io"
	"io/ioutil"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/antctl/handlers"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/scheme"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

// unixDomainSockAddr is the address for antctl server in local mode.
const unixDomainSockAddr = "/var/run/antctl.sock"

var systemGroup = schema.GroupVersion{Group: "system.antrea.tanzu.vmware.com", Version: "v1beta1"}

type transformedVersionResponse struct {
	handlers.ComponentVersionResponse `json:",inline" yaml:",inline"`
	AntctlVersion                     string `json:"antctlVersion" yaml:"antctlVersion"`
}

// versionTransform is the AddonTransform for the version command. This function
// will try to parse the response as a ComponentVersionResponse and then populate
// it with the version of antctl to a transformedVersionResponse object.
func versionTransform(reader io.Reader, _ bool) (interface{}, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	klog.Infof("version transform received: %s", string(b))
	cv := new(handlers.ComponentVersionResponse)
	err = json.Unmarshal(b, cv)
	if err != nil {
		return nil, err
	}
	resp := &transformedVersionResponse{
		ComponentVersionResponse: *cv,
		AntctlVersion:            version.GetFullVersion(),
	}
	return resp, nil
}

// CommandList defines all commands that could be used in the antctl for both agent
// and controller. The unit test "TestCommandListValidation" ensures it to be valid.
var CommandList = &commandList{
	definitions: []commandDefinition{
		{
			Use:                 "version",
			Short:               "Print version information",
			Long:                "Print version information of the antctl and the ${component}",
			HandlerFactory:      new(handlers.Version),
			GroupVersion:        &systemGroup,
			TransformedResponse: reflect.TypeOf(transformedVersionResponse{}),
			Agent:               true,
			Controller:          true,
			SingleObject:        true,
			CommandGroup:        flat,
			AddonTransform:      versionTransform,
		},
		{
			Use:                 "agent-info",
			Short:               "Print agent's basic information",
			Long:                "Print agent's basic information including version, node subnet, OVS info, AgentConditions, etc.",
			HandlerFactory:      new(handlers.AgentInfo),
			GroupVersion:        &systemGroup,
			TransformedResponse: reflect.TypeOf(handlers.AntreaAgentInfoResponse{}),
			Agent:               true,
			SingleObject:        true,
			CommandGroup:        flat,
		},
	},
	codec: scheme.Codecs,
}
