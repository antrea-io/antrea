// Copyright 2021 Antrea Authors.
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

package integration

import corev1 "k8s.io/api/core/v1"

var (
	addr1 = corev1.EndpointAddress{
		IP:       "192.168.17.11",
		Hostname: "pod1",
	}
	addr2 = corev1.EndpointAddress{
		IP:       "192.168.17.12",
		Hostname: "pod2",
	}
	addr3 = corev1.EndpointAddress{
		IP:       "192.168.17.13",
		Hostname: "pod3",
	}
	epPorts = []corev1.EndpointPort{
		{
			Name:     "http",
			Port:     80,
			Protocol: corev1.ProtocolTCP,
		},
	}
	svcPorts = []corev1.ServicePort{
		{
			Name:     "http",
			Protocol: corev1.ProtocolTCP,
			Port:     80,
		},
	}
)
