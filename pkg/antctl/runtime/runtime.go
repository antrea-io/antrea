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

package runtime

import (
	"os"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	ModeController string = "controller"
	ModeAgent      string = "agent"
)

var (
	// Mode tells which mode antctl is running against.
	Mode  string
	InPod bool
)

func ResolveKubeconfig(path string) (*rest.Config, error) {
	var err error
	if len(path) == 0 {
		var hasIt bool
		path, hasIt = os.LookupEnv("KUBECONFIG")
		if !hasIt || len(strings.TrimSpace(path)) == 0 {
			path = clientcmd.RecommendedHomeFile
		}
	}
	if _, err = os.Stat(path); path == clientcmd.RecommendedHomeFile && os.IsNotExist(err) {
		return rest.InClusterConfig()
	} else {
		return clientcmd.BuildConfigFromFlags("", path)
	}
}

func init() {
	podName, found := os.LookupEnv("POD_NAME")
	InPod = found && (strings.HasPrefix(podName, "antrea-agent") || strings.HasPrefix(podName, "antrea-controller"))
	if strings.HasPrefix(podName, "antrea-agent") {
		Mode = ModeAgent
	} else {
		Mode = ModeController
	}
}
