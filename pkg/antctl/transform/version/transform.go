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

package version

import (
	"encoding/json"
	"io"
	"io/ioutil"

	k8sversion "k8s.io/apimachinery/pkg/version"
	"k8s.io/klog"

	antreaversion "github.com/vmware-tanzu/antrea/pkg/version"
)

type Response struct {
	ServerVersion string `json:"serverVersion,omitempty" yaml:"serverVersion,omitempty"`
	ClientVersion string `json:"clientVersion,omitempty" yaml:"clientVersion,omitempty"`
}

// Transform is the AddonTransform for the version command. This function
// will try to parse the response as the ServerVersion, get the ClientVersion,
// and return a Response object.
func Transform(reader io.Reader, _ bool) (interface{}, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	klog.Infof("version transform received: %s", string(b))
	v := new(k8sversion.Info)
	err = json.Unmarshal(b, v)
	if err != nil {
		return nil, err
	}
	serverVersion := v.GitVersion
	if len(v.GitCommit) > 0 {
		serverVersion += "-" + v.GitCommit
	}
	if len(v.GitTreeState) > 0 {
		serverVersion += "." + v.GitTreeState
	}
	resp := &Response{
		ServerVersion: serverVersion,
		ClientVersion: antreaversion.GetFullVersion(),
	}
	return resp, nil
}
