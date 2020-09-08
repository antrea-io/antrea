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

package networkpolicy

import (
	"errors"
	"fmt"
	"net"
	"log"
	"os"

	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const (
	logDir string = "/var/log/antrea/networkpolicy/"
)

var (
	CNPLogger    *log.Logger
)

func InitLogger() {
	// logging file should be /var/log/antrea/networkpolicy/cnp.log
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	}
	file, err := os.OpenFile(logDir + "cnp.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		klog.Errorf("Failed to initiate logger %v", err)
	}

	CNPLogger = log.New(file, "CNP: ", log.Ldate|log.Ltime|log.Lshortfile)
	klog.Info("Initiated CNPLogger for audit logging")
}

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if pktIn == nil {
		return errors.New("empty packetin for CNP")
	}
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	tableID := binding.TableIDType(pktIn.TableId)

	ob := new(opsv1alpha1.Observation)
	// Get ingress/egress reg
	for _, table := range openflow.GetCNPEgressTables() {
		if tableID == table {
			match = getMatchRegField(matchers, uint32(openflow.EgressReg))
		}
	}
	for _, table := range openflow.GetCNPIngressTables() {
		if tableID == table {
			match = getMatchRegField(matchers, uint32(openflow.IngressReg))
		}
	}

	// Get source destination IP and protocol
	var obProtocol uint8
	if pktIn.Data.Ethertype == 0x800 {
		ipPacket, ok := pktIn.Data.Data.(*protocol.IPv4)
		if !ok {
			return errors.New("invalid IPv4 packet")
		}
		ob.TranslatedSrcIP = ipPacket.NWSrc.String()
		ob.TranslatedDstIP = ipPacket.NWDst.String()
		obProtocol = ipPacket.Protocol
	}

	// Get table ID
	ob.Component = opsv1alpha1.NetworkPolicy
	ob.ComponentInfo = openflow.GetFlowTableName(tableID)

	// Get network policy full name, CNP is not namespaced
	info, err := getInfoInReg(match, nil)
	if err != nil {
		return err
	}
	npName, npNamespace := c.ofClient.GetPolicyFromConjunction(info)
	ob.NetworkPolicy = getNetworkPolicyFullName(npName, npNamespace)

	// Get OF priority of the conjunction
	ofPriority := c.ofClient.GetPriorityFromConjunction(info)

	// Get disposition Allow or Drop
	match = getMatchRegField(matchers, uint32(openflow.DispositionReg))
	info, err = getInfoInReg(match, nil)
	if err != nil {
		return err
	}
	disposition := "Drop"
	if info == 1 {
		disposition = "Allow"
	}

	// Store log file
	CNPLogger.Printf("%s %s %s Priority: %s SRC: %s DEST: %s Protocol: %d", ob.ComponentInfo, ob.NetworkPolicy, disposition, ob.TranslatedSrcIP, ofPriority, ob.TranslatedDstIP, obProtocol)
	return nil
}

func getNetworkPolicyFullName(npName string, npNamespace string) string {
	if npName == "" || npNamespace == "" {
		return npName
	} else {
		return fmt.Sprintf("%s/%s", npNamespace, npName)
	}
}

func getMatchRegField(matchers *ofctrl.Matchers, regNum uint32) *ofctrl.MatchField {
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_REG%d", regNum))
}

func getInfoInReg(regMatch *ofctrl.MatchField, rng *openflow13.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*ofctrl.NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be got")
	}
	if rng != nil {
		return ofctrl.GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}

func getInfoInCtNwDstField(matchers *ofctrl.Matchers) (string, error) {
	match := matchers.GetMatchByName("NXM_NX_CT_NW_DST")
	if match == nil {
		return "", nil
	}
	regValue, ok := match.GetValue().(net.IP)
	if !ok {
		return "", errors.New("packet-in conntrack IP destination value cannot be retrieved from metadata")
	}
	return regValue.String(), nil
}