// +build !windows
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

package proxy

import (
	"net"

	"k8s.io/klog"

	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

// installLoadBalancerServiceFlows install OpenFlow entries for LoadBalancer Service.
// The rules for traffic from local Pod to LoadBalancer Service are same with rules for Cluster Service.
// For the LoadBalancer Service traffic from outside, kube-proxy will handle it.
func (p *Proxier) installLoadBalancerServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) error {
	if err := p.ofClient.InstallServiceFlows(groupID, svcIP, svcPort, protocol, affinityTimeout); err != nil {
		klog.Errorf("Error when installing LoadBalancer Service flows: %v", err)
		return err
	}
	return nil
}
