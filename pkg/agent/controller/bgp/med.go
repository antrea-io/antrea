// Copyright 2026 Antrea Authors
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

package bgp

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/memberlist"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

const (
	// defaultMEDBaseValue is the MED advertised by the most preferred Node when
	// `spec.advertisements.service.med.baseValue` is not set. It is deliberately not 0, so that the
	// paths advertised by the other Nodes can be assigned a higher (less preferred) value, and so
	// that a peer which is configured to treat a missing MED as 0 does not prefer a path without a
	// MED over the paths advertised by Antrea.
	defaultMEDBaseValue = uint32(100)
	// defaultMEDStep is the MED increment applied per Node rank when
	// `spec.advertisements.service.med.step` is not set.
	defaultMEDStep = uint32(100)
	// maxMED is the largest value that fits in the 4-octet MULTI_EXIT_DISC attribute. Computed MED
	// values are capped at it instead of wrapping around, which would make a low-ranked Node the
	// most preferred one.
	maxMED = uint32(math.MaxUint32)
	// maxMEDMaxAdvertisingNodes is the upper bound accepted for
	// `spec.advertisements.service.med.maxAdvertisingNodes`.
	maxMEDMaxAdvertisingNodes = 65535
)

// medConfig is the effective, validated MED configuration derived from a BGPPolicy, possibly
// overridden per Service by the Service annotations.
type medConfig struct {
	mode      v1alpha1.MEDMode
	baseValue uint32
	step      uint32
	// maxAdvertisingNodes is the maximum number of Nodes advertising each IP in the NodePriority
	// mode. 0 means no limit.
	maxAdvertisingNodes int
	// allowServiceOverride reports whether the Service annotations may override this configuration.
	allowServiceOverride bool
}

// disabled reports whether no MED attribute should be attached to the advertised routes.
func (c medConfig) disabled() bool {
	return c.mode == v1alpha1.MEDModeNone || c.mode == ""
}

// medForRank returns the MED that the Node with the given rank should advertise. Rank 0 is the most
// preferred Node, which advertises the base value.
func (c medConfig) medForRank(rank int) uint32 {
	if rank <= 0 {
		return c.baseValue
	}
	// Perform the arithmetic in 64 bits and saturate, so that a large base value, step or rank
	// cannot wrap around and turn a backup path into the preferred one.
	med := uint64(c.baseValue) + uint64(c.step)*uint64(rank)
	if med > uint64(maxMED) {
		return maxMED
	}
	return uint32(med)
}

// getMEDConfig converts the MED configuration of a ServiceAdvertisement into a medConfig, filling in
// the defaults. An invalid configuration is reported as an error and must be treated as disabled by
// the caller: BGPPolicy is not validated by a webhook, so the CRD schema is the only guardrail and
// the controller must not panic or advertise nonsense because of a value it did not expect.
func getMEDConfig(advertisement *v1alpha1.ServiceAdvertisement) (medConfig, error) {
	conf := medConfig{
		mode:      v1alpha1.MEDModeNone,
		baseValue: defaultMEDBaseValue,
		step:      defaultMEDStep,
		// MED is opt-in at the BGPPolicy level: the Service annotations are only honored once
		// `spec.advertisements.service.med` is set, so that adding an annotation to a Service cannot
		// change how its IPs are advertised in a cluster whose BGPPolicy does not mention MED.
		allowServiceOverride: false,
	}
	if advertisement == nil || advertisement.MED == nil {
		return conf, nil
	}
	med := advertisement.MED
	conf.allowServiceOverride = true

	switch med.Mode {
	case "", v1alpha1.MEDModeNone:
		conf.mode = v1alpha1.MEDModeNone
	case v1alpha1.MEDModeStatic, v1alpha1.MEDModeNodePriority:
		conf.mode = med.Mode
	default:
		return medConfig{mode: v1alpha1.MEDModeNone}, fmt.Errorf("invalid MED mode %q", med.Mode)
	}

	if med.BaseValue != nil {
		v, err := toMEDValue(*med.BaseValue)
		if err != nil {
			return medConfig{mode: v1alpha1.MEDModeNone}, fmt.Errorf("invalid MED baseValue: %w", err)
		}
		conf.baseValue = v
	}
	if med.Step != nil {
		v, err := toMEDValue(*med.Step)
		if err != nil {
			return medConfig{mode: v1alpha1.MEDModeNone}, fmt.Errorf("invalid MED step: %w", err)
		}
		if v == 0 {
			return medConfig{mode: v1alpha1.MEDModeNone}, fmt.Errorf("invalid MED step: must be greater than 0")
		}
		conf.step = v
	}
	if med.MaxAdvertisingNodes != nil {
		v := *med.MaxAdvertisingNodes
		if v < 0 || v > maxMEDMaxAdvertisingNodes {
			return medConfig{mode: v1alpha1.MEDModeNone}, fmt.Errorf("invalid MED maxAdvertisingNodes %d: must be in the range [0, %d]", v, maxMEDMaxAdvertisingNodes)
		}
		conf.maxAdvertisingNodes = int(v)
	}
	if med.AllowServiceOverride != nil {
		conf.allowServiceOverride = *med.AllowServiceOverride
	}
	return conf, nil
}

// applyServiceMEDOverrides returns the medConfig to use for a specific Service, applying the
// `service.antrea.io/bgp-med` and `service.antrea.io/bgp-med-mode` annotations when the BGPPolicy
// allows it. Invalid annotation values are reported as an error and ignored by the caller, which
// keeps the BGPPolicy configuration in effect: a typo in a Service annotation must not silently
// remove the Service IP from the routing table.
func applyServiceMEDOverrides(conf medConfig, svc *corev1.Service) (medConfig, error) {
	if !conf.allowServiceOverride {
		return conf, nil
	}
	if modeStr, exists := svc.Annotations[types.ServiceBGPMEDModeAnnotationKey]; exists {
		switch v1alpha1.MEDMode(modeStr) {
		case v1alpha1.MEDModeNone, v1alpha1.MEDModeStatic, v1alpha1.MEDModeNodePriority:
			conf.mode = v1alpha1.MEDMode(modeStr)
		default:
			return conf, fmt.Errorf("invalid value %q for annotation %s", modeStr, types.ServiceBGPMEDModeAnnotationKey)
		}
	}
	if baseStr, exists := svc.Annotations[types.ServiceBGPMEDAnnotationKey]; exists {
		parsed, err := strconv.ParseInt(baseStr, 10, 64)
		if err != nil {
			return conf, fmt.Errorf("invalid value %q for annotation %s: %w", baseStr, types.ServiceBGPMEDAnnotationKey, err)
		}
		v, err := toMEDValue(parsed)
		if err != nil {
			return conf, fmt.Errorf("invalid value %q for annotation %s: %w", baseStr, types.ServiceBGPMEDAnnotationKey, err)
		}
		conf.baseValue = v
	}
	return conf, nil
}

func toMEDValue(v int64) (uint32, error) {
	if v < 0 || v > int64(maxMED) {
		return 0, fmt.Errorf("value %d is out of the range [0, %d]", v, maxMED)
	}
	return uint32(v), nil
}

// serviceMEDContext caches everything that is needed to compute the MED of the IPs of a single
// Service, so that the per-Service work (resolving the ExternalIPPool, listing the EndpointSlices)
// is done once instead of once per IP.
type serviceMEDContext struct {
	c    *Controller
	svc  *corev1.Service
	conf medConfig
	// externalIPPool is the ExternalIPPool the Service allocates its LoadBalancer IP from, empty if
	// the Service does not use one.
	externalIPPool string
	// restrictToHealthyEndpoints reports whether the Nodes eligible for ranking must be restricted to
	// the ones hosting a healthy Endpoint, which mirrors the filter that the ServiceExternalIP
	// controller applies when it elects the owner of the IP. Keeping the two in sync is what
	// guarantees that the owner of the IP is the Node which advertises the most preferred path.
	restrictToHealthyEndpoints bool
	// healthyEndpointNodes caches the result of nodesWithHealthyEndpoints per address family, so
	// that the EndpointSlices of the Service are only walked once per family.
	healthyEndpointNodes map[discovery.AddressType]sets.Set[string]
	// rankable reports whether the IPs allocated from externalIPPool can be ranked.
	rankable bool
}

// rankFilters returns the filters restricting the Nodes eligible to advertise ip.
func (ctx *serviceMEDContext) rankFilters(ip string) []func(string) bool {
	if !ctx.restrictToHealthyEndpoints {
		return nil
	}
	// On a dual-stack cluster the Endpoints of the two address families may live on different Nodes,
	// so only the EndpointSlices matching the family of the advertised IP are considered.
	addressType := discovery.AddressTypeIPv4
	if utilnet.IsIPv6String(ip) {
		addressType = discovery.AddressTypeIPv6
	}
	nodes, exists := ctx.healthyEndpointNodes[addressType]
	if !exists {
		nodes = ctx.c.nodesWithHealthyEndpoints(ctx.svc, addressType)
		ctx.healthyEndpointNodes[addressType] = nodes
	}
	return []func(string) bool{func(node string) bool {
		return nodes.Has(node)
	}}
}

// newServiceMEDContext builds the MED context of a Service. conf must already include the overrides
// from the Service annotations.
func (c *Controller) newServiceMEDContext(svc *corev1.Service, conf medConfig) *serviceMEDContext {
	ctx := &serviceMEDContext{c: c, svc: svc, conf: conf}
	if conf.mode != v1alpha1.MEDModeNodePriority {
		return ctx
	}
	ctx.externalIPPool = svc.Annotations[types.ServiceExternalIPPoolAnnotationKey]
	if ctx.externalIPPool == "" {
		return ctx
	}
	if c.cluster == nil {
		// Without the memberlist cluster there is no ExternalIPPool membership to rank against. This
		// can only happen if both the Egress and the ServiceExternalIP features are disabled, in
		// which case no IP is allocated from an ExternalIPPool in the first place.
		klog.V(4).InfoS("Cannot rank the Nodes of the ExternalIPPool because the memberlist cluster is not running, falling back to the Static MED mode",
			"Service", klog.KObj(svc), "ExternalIPPool", ctx.externalIPPool)
		return ctx
	}
	ctx.rankable = true
	ctx.restrictToHealthyEndpoints = svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal
	ctx.healthyEndpointNodes = make(map[discovery.AddressType]sets.Set[string], 2)
	c.warnIfNotDSR(svc)
	return ctx
}

// medForServiceIP returns the MED that the local Node should advertise for a Service IP, and
// whether the local Node should advertise it at all.
func (ctx *serviceMEDContext) medForServiceIP(ip string, routeType AdvertisedRouteType) (uint32, bool) {
	if ctx.conf.disabled() {
		return 0, true
	}
	// Only the LoadBalancer IPs of a Service can be allocated from an ExternalIPPool. The other
	// Service IPs are reachable through every Node, so there is nothing to rank: they are advertised
	// with the base value, exactly as in the Static mode.
	if !ctx.rankable || routeType != ServiceLoadBalancerIP {
		return ctx.conf.baseValue, true
	}

	nodes, err := ctx.c.cluster.SelectNodesForIP(ip, ctx.externalIPPool, ctx.conf.maxAdvertisingNodes, ctx.rankFilters(ip)...)
	if err != nil {
		if errors.Is(err, memberlist.ErrNoNodeAvailable) {
			// No Node can serve the IP, e.g. the Service uses `externalTrafficPolicy: Local` and has
			// no Endpoint anywhere. Withdrawing the IP is what the BGP peers need to stop sending
			// traffic that would be dropped.
			klog.V(2).InfoS("No Node is eligible to advertise the Service IP", "Service", klog.KObj(ctx.svc), "IP", ip, "ExternalIPPool", ctx.externalIPPool)
			return 0, false
		}
		// The local view of the ExternalIPPool is not ready yet, typically right after the Agent
		// started. Advertise the IP with the base value rather than withdrawing it: a temporarily
		// suboptimal path is much better than a black hole.
		klog.ErrorS(err, "Failed to rank the Nodes of the ExternalIPPool, advertising the Service IP with the base MED",
			"Service", klog.KObj(ctx.svc), "IP", ip, "ExternalIPPool", ctx.externalIPPool)
		return ctx.conf.baseValue, true
	}

	rank := slices.Index(nodes, ctx.c.nodeName)
	if rank < 0 {
		// The local Node is not part of the ExternalIPPool, has no local Endpoint for a Service using
		// `externalTrafficPolicy: Local`, or is ranked beyond maxAdvertisingNodes.
		return 0, false
	}
	return ctx.conf.medForRank(rank), true
}

// nodesWithHealthyEndpoints returns the Nodes which have at least one Endpoint of the given address
// family that can serve the traffic of the Service. It mirrors the equivalent function of the
// ServiceExternalIP controller, which is what the owner of the IP is elected with.
func (c *Controller) nodesWithHealthyEndpoints(svc *corev1.Service, addressType discovery.AddressType) sets.Set[string] {
	nodes := sets.New[string]()
	labelSelector := labels.Set{discovery.LabelServiceName: svc.GetName()}.AsSelector()
	endpointSlices, _ := c.endpointSliceLister.EndpointSlices(svc.GetNamespace()).List(labelSelector)
	for _, eps := range endpointSlices {
		if eps.AddressType != addressType {
			continue
		}
		for _, ep := range eps.Endpoints {
			if ep.NodeName == nil {
				continue
			}
			// The ready condition is nil or true when the Endpoint can serve traffic; when it is
			// false, the Endpoint may still be draining existing connections, which the serving
			// condition reports.
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready ||
				ep.Conditions.Serving == nil || *ep.Conditions.Serving {
				nodes.Insert(*ep.NodeName)
			}
		}
	}
	return nodes
}

// warnIfNotDSR logs once if the NodePriority MED mode is used for a Service which does not use DSR
// and does not restrict the traffic to the Nodes hosting its Endpoints. That configuration works,
// but the Nodes which do not host an Endpoint SNAT the traffic they receive, so the backend Pods see
// the Node IP instead of the client IP.
func (c *Controller) warnIfNotDSR(svc *corev1.Service) {
	if svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
		return
	}
	mode := c.defaultLoadBalancerMode
	if modeStr, exists := svc.Annotations[types.ServiceLoadBalancerModeAnnotationKey]; exists {
		if ok, m := config.GetLoadBalancerModeFromStr(modeStr); ok {
			mode = m
		}
	}
	if c.dsrEnabled && mode == config.LoadBalancerModeDSR {
		return
	}
	c.warnNonDSROnce.Do(func() {
		klog.InfoS("The NodePriority MED mode advertises a Service IP from Nodes which may not host any of its Endpoints; without DSR those Nodes SNAT the ingress traffic and the backend Pods do not see the client IP. Enable the LoadBalancerModeDSR feature gate and set the Service annotation to \"dsr\", or use \"externalTrafficPolicy: Local\"",
			"Service", klog.KObj(svc), "LoadBalancerModeDSREnabled", c.dsrEnabled, "loadBalancerMode", mode)
	})
}
