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
	"log"
	"os"
	"path/filepath"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/util/ip"
	"github.com/vmware-tanzu/antrea/pkg/util/logdir"
)

const (
	logfileSubdir string = "networkpolicy"
	logfileName   string = "np.log"
)

var (
	AntreaPolicyLogger *log.Logger
)

// logInfo will be set by retrieving info from packetin and register
type logInfo struct {
	tableName   string // name of the table sending packetin
	npRef       string // Network Policy name reference for Antrea NetworkPolicy
	disposition string // Allow/Drop of the rule sending packetin
	ofPriority  string // openflow priority of the flow sending packetin
	srcIP       string // source IP of the traffic logged
	destIP      string // destination IP of the traffic logged
	pktLength   uint16 // packet length of packetin
	protocolStr string // protocol of the traffic logged
}

// initLogger is called while newing Antrea network policy agent controller.
// Customize AntreaPolicyLogger specifically for Antrea Policies audit logging.
func initLogger() error {
	logDir := filepath.Join(logdir.GetLogDir(), logfileSubdir)
	logFile := filepath.Join(logDir, logfileName)
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	}

	// Use lumberjack log file rot
	logOutput := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    500,  // allow max 500 megabytes for one log file
		MaxBackups: 3,    // allow max 3 old log file backups
		MaxAge:     28,   // allow max 28 days maintenance of old log files
		Compress:   true, // compress the old log files for backup
	}
	AntreaPolicyLogger = log.New(logOutput, "", log.Ldate|log.Lmicroseconds)
	klog.V(2).Infof("Initialized Antrea-native Policy Logger for audit logging with log file '%s'", logFile)
	return nil
}

// HandlePacketIn is the packetin handler registered to openflow by Antrea network policy agent controller.
// Retrieves information from openflow reg, controller cache, packetin packet to log.
func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if pktIn == nil {
		return errors.New("empty packetin for Antrea Policy")
	}

	ob := new(logInfo)

	// Get Network Policy log info
	err := getNetworkPolicyInfo(pktIn, c, ob)
	if err != nil {
		return fmt.Errorf("received error while retrieving NetworkPolicy info: %v", err)
	}

	// Get packet log info
	err = getPacketInfo(pktIn, ob)
	if err != nil {
		return fmt.Errorf("received error while handling packetin for NetworkPolicy: %v", err)
	}

	// Store log file
	AntreaPolicyLogger.Printf("%s %s %s %s SRC: %s DEST: %s %d %s", ob.tableName, ob.npRef, ob.disposition, ob.ofPriority, ob.srcIP, ob.destIP, ob.pktLength, ob.protocolStr)
	return nil
}

// getMatchRegField returns match to the regNum register.
func getMatchRegField(matchers *ofctrl.Matchers, regNum uint32) *ofctrl.MatchField {
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_REG%d", regNum))
}

// getMatch receives ofctrl matchers and table id, match field.
// Modifies match field to Ingress/Egress register based on tableID.
func getMatch(matchers *ofctrl.Matchers, tableID binding.TableIDType, disposition uint32) *ofctrl.MatchField {
	// Get match from CNPDropConjunctionIDReg if disposition is drop
	if disposition == openflow.DispositionDrop {
		return getMatchRegField(matchers, uint32(openflow.CNPDropConjunctionIDReg))
	}
	// Get match from ingress/egress reg if disposition is allow
	for _, table := range append(openflow.GetAntreaPolicyEgressTables(), openflow.EgressRuleTable) {
		if tableID == table {
			return getMatchRegField(matchers, uint32(openflow.EgressReg))
		}
	}
	for _, table := range append(openflow.GetAntreaPolicyIngressTables(), openflow.IngressRuleTable) {
		if tableID == table {
			return getMatchRegField(matchers, uint32(openflow.IngressReg))
		}
	}
	return nil
}

// getInfoInReg unloads and returns data stored in the match field.
func getInfoInReg(regMatch *ofctrl.MatchField, rng *openflow13.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*ofctrl.NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be retrieved")
	}
	if rng != nil {
		return ofctrl.GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}

// getNetworkPolicyInfo fills in tableName, npName, ofPriority, disposition of logInfo ob.
func getNetworkPolicyInfo(pktIn *ofctrl.PacketIn, c *Controller, ob *logInfo) error {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	// Get table name
	tableID := binding.TableIDType(pktIn.TableId)
	ob.tableName = openflow.GetFlowTableName(tableID)

	// Get disposition Allow or Drop
	match = getMatchRegField(matchers, uint32(openflow.DispositionMarkReg))
	info, err := getInfoInReg(match, openflow.APDispositionMarkRange.ToNXRange())
	if err != nil {
		return fmt.Errorf("received error while unloading disposition from reg: %v", err)
	}
	ob.disposition = openflow.DispositionToString[info]

	// Set match to corresponding ingress/egress reg according to disposition
	match = getMatch(matchers, tableID, info)

	// Get Network Policy full name and OF priority of the conjunction
	info, err = getInfoInReg(match, nil)
	if err != nil {
		return fmt.Errorf("received error while unloading conjunction id from reg: %v", err)
	}
	ob.npRef, ob.ofPriority = c.ofClient.GetPolicyInfoFromConjunction(info)

	return nil
}

// getPacketInfo fills in srcIP, destIP, pktLength, protocol of logInfo ob.
func getPacketInfo(pktIn *ofctrl.PacketIn, ob *logInfo) error {
	var prot uint8
	switch ipPkt := pktIn.Data.Data.(type) {
	case *protocol.IPv4:
		ob.srcIP = ipPkt.NWSrc.String()
		ob.destIP = ipPkt.NWDst.String()
		ob.pktLength = ipPkt.Length
		prot = ipPkt.Protocol
	case *protocol.IPv6:
		ob.srcIP = ipPkt.NWSrc.String()
		ob.destIP = ipPkt.NWDst.String()
		ob.pktLength = ipPkt.Length
		prot = ipPkt.NextHeader
	default:
		return errors.New("unsupported packet-in: should be a valid IPv4 or IPv6 packet")
	}

	ob.protocolStr = ip.IPProtocolNumberToString(prot, "UnknownProtocol")

	return nil
}
