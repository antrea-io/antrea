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

package providers

// Hides away specific characteristics of the K8s cluster. This should enable the same tests to be
// run on a variety of providers.
type ProviderInterface interface {
	RunCommandOnNode(nodeName string, cmd string) (code int, stdout string, stderr string, err error)
	// RunCommandOnNodeExt supports passing environment variables and writing the input to stdin.
	RunCommandOnNodeExt(nodeName, cmd string, envs map[string]string, stdin string, sudo bool) (code int, stdout string, stderr string, err error)
	GetKubeconfigPath() (string, error)
}
