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

package testing

import (
	"fmt"
	"strings"
)

const argsFormat = "IgnoreUnknown=1;K8S_POD_NAMESPACE=%s;K8S_POD_NAME=%s;K8S_POD_INFRA_CONTAINER_ID=%s"

func GenerateCNIArgs(podName, podNamespace, podInfraContainerID string) string {
	return fmt.Sprintf(argsFormat, podNamespace, podName, podInfraContainerID)
}

func ParseCNIArgs(args string) (podName, podNamespace, podInfraContainerID string) {
	strs := strings.Split(args, ";")
	for _, str := range strs {
		fields := strings.Split(str, "=")
		if len(fields) == 2 {
			switch fields[0] {
			case "K8S_POD_NAMESPACE":
				podNamespace = fields[1]
			case "K8S_POD_NAME":
				podName = fields[1]
			case "K8S_POD_INFRA_CONTAINER_ID":
				podInfraContainerID = fields[1]
			}
		}
	}
	return
}
