package connections

import (
	"encoding/binary"
	"fmt"

	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/objectstore"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"
)

// func NewConntrackConnectionAugmenter(podStore objectstore.PodStore, proxier proxy.Proxier, npQuerier querier.AgentNetworkPolicyInfoQuerier, egressQuerier querier.EgressQuerier, nodeRouteController *noderoute.Controller, isNetworkPolicyOnly bool) Augmenter {
// 	aug := &conntrackConnectionAugmenter{
// 		podInfoAug: &podInfoAugmenter{
// 			podStore: podStore,
// 		},
// 		serviceInfoAug: &serviceInfoAugmenter{
// 			antreaProxier: proxier,
// 		},
// 		networkPolicyAug: &networkPolicyMetadataAugmenter{
// 			networkPolicyQuerier: npQuerier,
// 		},
// 		egressInfoAug: &egressInfoAugmenter{
// 			nodeRouteController: nodeRouteController,
// 			egressQuerier:       egressQuerier,
// 			isNetworkPolicyOnly: isNetworkPolicyOnly,
// 		},
// 	}

// 	return aug
// }

// type conntrackConnectionAugmenter struct {
// 	podInfoAug       *podInfoAugmenter
// 	serviceInfoAug   *serviceInfoAugmenter
// 	networkPolicyAug *networkPolicyMetadataAugmenter
// 	egressInfoAug    *egressInfoAugmenter
// }

// func (aug *conntrackConnectionAugmenter) Augment(conn *connection.Connection, opts ...AugmentOpt) *connection.Connection {
// 	conn = aug.podInfoAug.Augment(conn)
// 	// TODO: make this a function of connection.Connection
// 	if conn.SourcePodName == "" && conn.DestinationPodName == "" {
// 		// We don't add connections to connection map or expirePriorityQueue if we can't find the pod
// 		// information for both srcPod and dstPod
// 		klog.V(5).InfoS("Skip this connection as we cannot map any of the connection IPs to a local Pod", "srcIP", conn.FlowKey.SourceAddress.String(), "dstIP", conn.FlowKey.DestinationAddress.String())
// 		return nil
// 	}
// 	aug.serviceInfoAug.Augment(conn)
// 	aug.networkPolicyAug.Augment(conn)
// 	aug.egressInfoAug.Augment(conn)

// 	if conn.StartTime.IsZero() {
// 		now := time.Now()
// 		conn.StartTime = now
// 		conn.StopTime = now
// 		conn.LastExportTime = conn.StartTime
// 	}

// 	conn.IsActive = true
// 	conn.IsPresent = true

// 	return conn
// }

// func NewDenyConnectionAugmenter(podStore objectstore.PodStore, proxier proxy.Proxier, egressQuerier querier.EgressQuerier, nodeRouteController *noderoute.Controller, isNetworkPolicyOnly bool) Augmenter {
// 	return &denyConnectionAugmenter{
// 		podInfoAug: &podInfoAugmenter{
// 			podStore: podStore,
// 		},
// 		serviceInfoAug: &serviceInfoAugmenter{
// 			antreaProxier: proxier,
// 		},
// 		egressInfoAug: &egressInfoAugmenter{
// 			nodeRouteController: nodeRouteController,
// 			egressQuerier:       egressQuerier,
// 			isNetworkPolicyOnly: isNetworkPolicyOnly,
// 		},
// 	}
// }

// type denyConnectionAugmenter struct {
// 	podInfoAug     *podInfoAugmenter
// 	serviceInfoAug *serviceInfoAugmenter
// 	egressInfoAug  *egressInfoAugmenter
// }

// func (aug *denyConnectionAugmenter) Augment(conn *connection.Connection, opts ...AugmentOpt) *connection.Connection {
// 	conn = aug.podInfoAug.Augment(conn)
// 	// TODO: make this a function of connection.Connection
// 	if conn.SourcePodName == "" && conn.DestinationPodName == "" {
// 		// We don't add connections to connection map or expirePriorityQueue if we can't find the pod
// 		// information for both srcPod and dstPod
// 		klog.V(5).InfoS("Skip this connection as we cannot map any of the connection IPs to a local Pod", "srcIP", conn.FlowKey.SourceAddress.String(), "dstIP", conn.FlowKey.DestinationAddress.String())
// 		return nil
// 	}
// 	aug.serviceInfoAug.Augment(conn)
// 	aug.egressInfoAug.Augment(conn)

// 	if conn.StartTime.IsZero() {
// 		now := time.Now()
// 		conn.StartTime = now
// 		conn.StopTime = now
// 		conn.LastExportTime = conn.StartTime
// 	}

// 	conn.IsActive = true

// 	return conn
// }

type podInfoAugmenter struct {
	podStore objectstore.PodStore
}

func (aug *podInfoAugmenter) Augment(conn *connection.Connection, opts ...AugmentOpt) {
	if aug.podStore == nil {
		klog.V(4).Info("Pod store is not available to retrieve local Pods information.")
		return
	}
	// sourceIP/destinationIP are mapped only to local pods and not remote pods.
	srcIP := conn.FlowKey.SourceAddress.String()
	dstIP := conn.FlowKey.DestinationAddress.String()

	srcPod, srcFound := aug.podStore.GetPodByIPAndTime(srcIP, conn.StartTime)
	dstPod, dstFound := aug.podStore.GetPodByIPAndTime(dstIP, conn.StartTime)
	if srcFound {
		conn.SourcePodName = srcPod.Name
		conn.SourcePodNamespace = srcPod.Namespace
		conn.SourcePodUID = string(srcPod.UID)
	}
	if dstFound {
		conn.DestinationPodName = dstPod.Name
		conn.DestinationPodNamespace = dstPod.Namespace
		conn.DestinationPodUID = string(dstPod.UID)
	}
	return
}

type serviceInfoAugmenter struct {
	antreaProxier proxy.Proxier
}

func (aug *serviceInfoAugmenter) Augment(conn *connection.Connection, opts ...AugmentOpt) {
	if conn.Mark&openflow.ServiceCTMark.GetRange().ToNXRange().ToUint32Mask() != openflow.ServiceCTMark.GetValue() {
		return
	}

	clusterIP := conn.OriginalDestinationAddress.String()
	svcPort := conn.OriginalDestinationPort

	// What's the difference between the commented block and this? When it's an
	// conntrack connection it only supports very specific ones?
	protocol := ip.IPProtocolNumberToString(conn.FlowKey.Protocol, "UnknownProtocol")
	// protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
	// if err != nil {
	// 	klog.InfoS("Could not retrieve Service protocol", "error", err)
	// 	return conn
	// }

	serviceStr := fmt.Sprintf("%s:%d/%s", clusterIP, svcPort, protocol)

	// resolve destination Service information
	if aug.antreaProxier != nil {
		servicePortName, exists := aug.antreaProxier.GetServiceByIP(serviceStr)
		if exists {
			conn.DestinationServicePortName = servicePortName.String()
		} else {
			klog.InfoS("Could not retrieve the Service info from antrea-agent-proxier", "serviceStr", serviceStr)
		}
	}
	return
}

type networkPolicyMetadataAugmenter struct {
	networkPolicyQuerier querier.AgentNetworkPolicyInfoQuerier
}

func (cs *networkPolicyMetadataAugmenter) Augment(conn *connection.Connection, opts ...AugmentOpt) {
	if len(conn.Labels) == 0 {
		return
	}
	klog.V(4).Infof("connection label: %x; label masks: %x", conn.Labels, conn.LabelsMask)

	// Retrieve NetworkPolicy Name and Namespace by using the ingress and egress
	// IDs stored in the connection label.
	ingressOfID := binary.LittleEndian.Uint32(conn.Labels[:4])
	if ingressOfID != 0 {
		policy := cs.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(ingressOfID)
		rule := cs.networkPolicyQuerier.GetRuleByFlowID(ingressOfID)
		if policy == nil || rule == nil {
			// This should not happen because the rule flow ID to rule mapping is
			// preserved for max(5s, flowPollInterval) even after the rule deletion.
			klog.Warningf("Cannot find NetworkPolicy or rule with ingressOfID %v", ingressOfID)
		} else {
			conn.IngressNetworkPolicyName = policy.Name
			conn.IngressNetworkPolicyNamespace = policy.Namespace
			conn.IngressNetworkPolicyUID = string(policy.UID)
			conn.IngressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
			conn.IngressNetworkPolicyRuleName = rule.Name
			conn.IngressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
		}
	}

	egressOfID := binary.LittleEndian.Uint32(conn.Labels[4:8])
	if egressOfID != 0 {
		policy := cs.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(egressOfID)
		rule := cs.networkPolicyQuerier.GetRuleByFlowID(egressOfID)
		if policy == nil || rule == nil {
			// This should not happen because the rule flow ID to rule mapping is
			// preserved for max(5s, flowPollInterval) even after the rule deletion.
			klog.Warningf("Cannot find NetworkPolicy or rule with egressOfID %v", egressOfID)
		} else {
			conn.EgressNetworkPolicyName = policy.Name
			conn.EgressNetworkPolicyNamespace = policy.Namespace
			conn.EgressNetworkPolicyUID = string(policy.UID)
			conn.EgressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
			conn.EgressNetworkPolicyRuleName = rule.Name
			conn.EgressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
		}
	}

	return
}

type egressInfoAugmenter struct {
	nodeRouteController *noderoute.Controller
	egressQuerier       querier.EgressQuerier
	isNetworkPolicyOnly bool
}

func (eca *egressInfoAugmenter) Augment(conn *connection.Connection, opts ...AugmentOpt) {
	egress, err := eca.egressQuerier.GetEgress(conn.SourcePodNamespace, conn.SourcePodName)
	if err != nil {
		// Egress is not enabled or no Egress is applied to this Pod
		return
	}
	conn.EgressName = egress.Name
	conn.EgressUID = string(egress.UID)
	conn.EgressIP = egress.EgressIP
	conn.EgressNodeName = egress.EgressNode

	return
}

func (exp *egressInfoAugmenter) findFlowType(conn connection.Connection) uint8 {
	// TODO: support Pod-To-External flows in network policy only mode.
	if exp.isNetworkPolicyOnly {
		if conn.SourcePodName == "" || conn.DestinationPodName == "" {
			return utils.FlowTypeInterNode
		}
		return utils.FlowTypeIntraNode
	}

	if exp.nodeRouteController == nil {
		klog.V(5).InfoS("Can't find flow type without nodeRouteController")
		return utils.FlowTypeUnspecified
	}
	srcIsPod, srcIsGw := exp.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.SourceAddress)
	dstIsPod, dstIsGw := exp.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.DestinationAddress)
	if srcIsGw || dstIsGw {
		// This matches what we do in filterAntreaConns but is more general as we consider
		// remote gateways as well.
		klog.V(5).InfoS("Flows where the source or destination IP is a gateway IP will not be exported")
		return utils.FlowTypeUnsupported
	}
	if !srcIsPod {
		klog.V(5).InfoS("Flows where the source is not a Pod will not be exported")
		return utils.FlowTypeUnsupported
	}
	if !dstIsPod {
		return utils.FlowTypeToExternal
	}
	if conn.SourcePodName == "" || conn.DestinationPodName == "" {
		return utils.FlowTypeInterNode
	}
	return utils.FlowTypeIntraNode
}
