// Copyright 2020 Antrea Authors
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

package ipfix

import (
	"sync"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"
)

var (
	_ IPFIXRegistry = (*ipfixRegistry)(nil)

	loadRegistry = sync.OnceFunc(func() {
		ipfixregistry.LoadRegistry()
		// Register Information Elements that are not yet in the go-ipfix library.
		// nodeSnatIPv4 (ID 173): SNAT IP for Pod-to-External flows using default Node SNAT.
		if err := ipfixregistry.PutInfoElement(*ipfixentities.NewInfoElement("nodeSnatIPv4", 173, 18, ipfixregistry.AntreaEnterpriseID, 4), ipfixregistry.AntreaEnterpriseID); err != nil {
			klog.ErrorS(err, "Failed to register nodeSnatIPv4 IE")
		}
		// nodeSnatIPv6 (ID 174): IPv6 variant.
		if err := ipfixregistry.PutInfoElement(*ipfixentities.NewInfoElement("nodeSnatIPv6", 174, 19, ipfixregistry.AntreaEnterpriseID, 16), ipfixregistry.AntreaEnterpriseID); err != nil {
			klog.ErrorS(err, "Failed to register nodeSnatIPv6 IE")
		}
		// nodeSnatPort (ID 175): SNAT port for Pod-to-External flows using default Node SNAT.
		if err := ipfixregistry.PutInfoElement(*ipfixentities.NewInfoElement("nodeSnatPort", 175, 2, ipfixregistry.AntreaEnterpriseID, 2), ipfixregistry.AntreaEnterpriseID); err != nil {
			klog.ErrorS(err, "Failed to register nodeSnatPort IE")
		}
	})
)

// IPFIXRegistry interface is added to facilitate unit testing without involving the code from go-ipfix library.
type IPFIXRegistry interface {
	LoadRegistry()
	GetInfoElement(name string, enterpriseID uint32) (*ipfixentities.InfoElement, error)
}

type ipfixRegistry struct{}

func NewIPFIXRegistry() *ipfixRegistry {
	return &ipfixRegistry{}
}

func (reg *ipfixRegistry) LoadRegistry() {
	loadRegistry()
}

func (reg *ipfixRegistry) GetInfoElement(name string, enterpriseID uint32) (*ipfixentities.InfoElement, error) {
	return ipfixregistry.GetInfoElement(name, enterpriseID)
}
