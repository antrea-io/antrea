// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"net"

	apitypes "k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

type IGMPNPRuleInfo struct {
	RuleAction v1beta1.RuleAction
	UUID       apitypes.UID
	NPType     *v1beta2.NetworkPolicyType
	Name       string
}

var (
	McastAllHosts   = net.ParseIP("224.0.0.1").To4()
	IGMPv3Router    = net.ParseIP("224.0.0.22").To4()
	_, McastCIDR, _ = net.ParseCIDR("224.0.0.0/4")
)

type McastNetworkPolicyController interface {
	// GetIGMPNPRuleInfo looks up the IGMP NetworkPolicy rule that matches the given Pod and groupAddress,
	// and returns the rule information if found.
	GetIGMPNPRuleInfo(podname, podNamespace string, groupAddress net.IP, igmpType uint8) (*IGMPNPRuleInfo, error)
}
