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
	"fmt"
	"os"
	"strings"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/util/runtime"
)

const (
	ModeController     string = "controller"
	ModeAgent          string = "agent"
	ModeFlowAggregator string = "flowaggregator"
)

var (
	// Mode tells which mode antctl is running against.
	Mode  string
	InPod bool
)

func ResolveKubeconfig(path string) (*rest.Config, error) {
	withExplicitPath := path != ""
	if !withExplicitPath {
		path = strings.TrimSpace(os.Getenv("KUBECONFIG"))
		if path == "" {
			path = clientcmd.RecommendedHomeFile
		}
	}
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if withExplicitPath {
			return nil, fmt.Errorf("failed to resolve kubeconfig: kubeconfig file does not exist at path '%s'", path)
		}
		config, inClusterErr := rest.InClusterConfig()
		if inClusterErr == nil {
			return config, nil
		}
		return nil, fmt.Errorf(
			"failed to resolve kubeconfig: neither a valid kubeconfig file was found at '%s', nor could InClusterConfig be used: %w",
			path, inClusterErr,
		)
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: path},
		&clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig from file at path '%s': %w", path, err)
	}
	return config, nil
}

func init() {
	podName, found := os.LookupEnv("POD_NAME")
	InPod = found && (strings.HasPrefix(podName, "antrea-agent") || strings.HasPrefix(podName, "antrea-controller") ||
		strings.HasPrefix(podName, "flow-aggregator"))

	if runtime.IsWindowsPlatform() && !InPod {
		if _, err := os.Stat(apis.APIServerLoopbackTokenPath); err == nil {
			InPod = true
			Mode = ModeAgent
			return
		}
	}

	if strings.HasPrefix(podName, "antrea-agent") {
		Mode = ModeAgent
	} else if strings.HasPrefix(podName, "flow-aggregator") {
		Mode = ModeFlowAggregator
	} else {
		Mode = ModeController
	}
}
