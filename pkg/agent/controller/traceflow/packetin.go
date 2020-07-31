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

package traceflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if !c.traceflowListerSynced() {
		return errors.New("traceflow controller is not started")
	}
	oldTf, nodeResult, err := c.parsePacketIn(pktIn)
	if err != nil {
		klog.Errorf("parsePacketIn error: %+v", err)
		return err
	}
	// Retry when update CRD conflict which caused by multiple agents updating one CRD at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		tf, err := c.traceflowInformer.Lister().Get(oldTf.Name)
		if err != nil {
			klog.Warningf("Get traceflow failed: %+v", err)
			return err
		}
		tf.Status.Results = append(tf.Status.Results, *nodeResult)
		tf, err = c.traceflowClient.OpsV1alpha1().Traceflows().UpdateStatus(context.TODO(), tf, v1.UpdateOptions{})
		if err != nil {
			klog.Warningf("Update traceflow failed: %+v", err)
			return err
		}
		klog.Infof("Updated traceflow %s: %+v", tf.Name, nodeResult)
		return nil
	})
	if err != nil {
		klog.Errorf("Update traceflow error: %+v", err)
	}
	return err
}

func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (*opsv1alpha1.Traceflow, *opsv1alpha1.NodeResult, error) {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField

	// Get data plane tag.
	if match = getMatchRegField(matchers, uint32(openflow.TraceflowReg)); match == nil {
		return nil, nil, errors.New("traceflow data plane tag not found")
	}
	rngTag := openflow13.NewNXRange(int(openflow.OfTraceflowMarkRange[0]), int(openflow.OfTraceflowMarkRange[1]))
	tag, err := getInfoInReg(match, rngTag)
	if err != nil {
		return nil, nil, err
	}

	// Get traceflow CRD from cache by data plane tag.
	tf, err := c.GetRunningTraceflowCRD(uint8(tag))
	if err != nil {
		return nil, nil, err
	}

	obs := make([]opsv1alpha1.Observation, 0)
	isSender := c.isSender(uint8(tag))
	tableID := pktIn.TableId

	if isSender {
		ob := new(opsv1alpha1.Observation)
		ob.Component = opsv1alpha1.SpoofGuard
		ob.Action = opsv1alpha1.Forwarded
		obs = append(obs, *ob)
	} else {
		ob := new(opsv1alpha1.Observation)
		ob.Component = opsv1alpha1.Forwarding
		ob.Action = opsv1alpha1.Received
		ob.ComponentInfo = openflow.GetFlowTableName(openflow.ClassifierTable)
		obs = append(obs, *ob)
	}

	// Collect egress conjunctionID and get NetworkPolicy from cache.
	if match = getMatchRegField(matchers, uint32(openflow.EgressReg)); match != nil {
		egressInfo, err := getInfoInReg(match, nil)
		if err != nil {
			return nil, nil, err
		}
		ob := new(opsv1alpha1.Observation)
		ob.Component = opsv1alpha1.NetworkPolicy
		ob.ComponentInfo = openflow.GetFlowTableName(openflow.EgressRuleTable)
		ob.Action = opsv1alpha1.Forwarded
		npName, npNamespace := c.ofClient.GetPolicyFromConjunction(egressInfo)
		if npName != "" {
			ob.NetworkPolicy = fmt.Sprintf("%s/%s", npNamespace, npName)
		}
		obs = append(obs, *ob)
	}

	// Collect ingress conjunctionID and get NetworkPolicy from cache.
	if match = getMatchRegField(matchers, uint32(openflow.IngressReg)); match != nil {
		ingressInfo, err := getInfoInReg(match, nil)
		if err != nil {
			return nil, nil, err
		}
		ob := new(opsv1alpha1.Observation)
		ob.Component = opsv1alpha1.NetworkPolicy
		ob.ComponentInfo = openflow.GetFlowTableName(openflow.IngressRuleTable)
		ob.Action = opsv1alpha1.Forwarded
		npName, npNamespace := c.ofClient.GetPolicyFromConjunction(ingressInfo)
		if npName != "" {
			ob.NetworkPolicy = fmt.Sprintf("%s/%s", npNamespace, npName)
		}
		obs = append(obs, *ob)
	}

	// Get drop table.
	if tableID == uint8(openflow.EgressDefaultTable) || tableID == uint8(openflow.IngressDefaultTable) {
		ob := new(opsv1alpha1.Observation)
		ob.Action = opsv1alpha1.Dropped
		ob.Component = opsv1alpha1.NetworkPolicy
		ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
		obs = append(obs, *ob)
	}

	// Get output table.
	if tableID == uint8(openflow.L2ForwardingOutTable) {
		ob := new(opsv1alpha1.Observation)
		tunnelDstIP := ""
		if match = getMatchTunnelDstField(matchers); match != nil {
			tunnelDstIP, err = getInfoInTunnelDst(match)
			if err != nil {
				return nil, nil, err
			}
		}
		if tunnelDstIP != "" && tunnelDstIP != c.nodeConfig.NodeIPAddr.IP.String() {
			ob.TunnelDstIP = tunnelDstIP
			ob.Action = opsv1alpha1.Forwarded
		} else {
			ob.Action = opsv1alpha1.Delivered
		}
		ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
		ob.Component = opsv1alpha1.Forwarding
		obs = append(obs, *ob)
	}

	nodeResult := opsv1alpha1.NodeResult{Node: c.nodeConfig.Name, Timestamp: time.Now().Unix(), Observations: obs}
	return tf, &nodeResult, nil
}

func getMatchRegField(matchers *ofctrl.Matchers, regNum uint32) *ofctrl.MatchField {
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_REG%d", regNum))
}

func getMatchTunnelDstField(matchers *ofctrl.Matchers) *ofctrl.MatchField {
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_TUN_IPV4_DST"))
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

func getInfoInTunnelDst(regMatch *ofctrl.MatchField) (string, error) {
	regValue, ok := regMatch.GetValue().(net.IP)
	if !ok {
		return "", errors.New("tunnel destination value cannot be got")
	}
	return regValue.String(), nil
}
