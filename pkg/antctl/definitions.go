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
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/vmware-tanzu/antrea/pkg/antctl/handlers"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/scheme"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

func versionTransform(obj interface{}) interface{} {
	if resp, ok := obj.(*handlers.VersionResponse); ok {
		resp.AntctlVersion = version.GetFullVersion()
		return resp
	} else {
		return obj
	}
}

var commands = []CommandOption{
	{
		Use:            "version",
		Short:          "Get the component version",
		Long:           "Get the component version",
		HandlerFactory: new(handlers.Version),
		ResponseStruct: new(handlers.VersionResponse),
		Agent:          true,
		Controller:     true,
		Singleton:      true,
		CommandGroup:   Flat,
		AddOnTransform: versionTransform,
	},
}

// Definition defines command related options of the antctl.
// Developers should run the generate below to check if the definition is valid when they made any change of it.
var Definition = &CommandBundle{
	CommandOptions: commands,
	GroupVersion:   &schema.GroupVersion{Group: "cli.antrea.io", Version: "v1"},
	Codec:          scheme.Codecs,
}
