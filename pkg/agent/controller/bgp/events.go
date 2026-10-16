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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/v2/pkg/client/clientset/versioned/scheme"
)

// Reasons of the Kubernetes Events that the controller records on BGPPolicies.
const (
	reasonBGPServerStarted      = "BGPServerStarted"
	reasonBGPServerStartFailed  = "BGPServerStartFailed"
	reasonBGPPeerConfigFailed   = "BGPPeerConfigFailed"
	reasonBGPPolicySyncFailed   = "BGPPolicySyncFailed"
	reasonBGPPolicyNotEffective = "BGPPolicyNotEffective"
	reasonBGPPeerUp             = "BGPPeerUp"
	reasonBGPPeerDown           = "BGPPeerDown"
)

const (
	actionApplyBGPPolicy = "ApplyBGPPolicy"
	actionMonitorBGPPeer = "MonitorBGPPeer"
)

// syncStepError associates the error of a step of a sync with the reason of the Event that reports it. Its message is
// the message of the wrapped error.
type syncStepError struct {
	reason string
	err    error
}

func (e *syncStepError) Error() string {
	return e.err.Error()
}

func (e *syncStepError) Unwrap() error {
	return e.err
}

// eventRecorder records the Kubernetes Events of the controller. Every Node that a BGPPolicy selects records its Events
// on that BGPPolicy, so the note of each Event names the Node.
type eventRecorder struct {
	k8sClient   kubernetes.Interface
	broadcaster events.EventBroadcaster
	// recorder is nil until start is called, because the broadcaster runs goroutines, which are only created when the
	// controller runs. The controller records no Event before that.
	recorder events.EventRecorder
}

func newEventRecorder(k8sClient kubernetes.Interface) *eventRecorder {
	return &eventRecorder{k8sClient: k8sClient}
}

// start sends the recorded Events to the Kubernetes API until stopCh is closed.
func (r *eventRecorder) start(stopCh <-chan struct{}) {
	r.broadcaster = events.NewBroadcaster(&events.EventSinkImpl{Interface: r.k8sClient.EventsV1()})
	r.recorder = r.broadcaster.NewRecorder(scheme.Scheme, controllerName)
	// The failures that Events report are also logged at the default verbosity.
	r.broadcaster.StartStructuredLogging(2)
	r.broadcaster.StartRecordingToSink(stopCh)
}

func (r *eventRecorder) shutdown() {
	r.broadcaster.Shutdown()
}

func (r *eventRecorder) eventf(regarding runtime.Object, eventType, reason, action, note string, args ...interface{}) {
	if r.recorder != nil {
		r.recorder.Eventf(regarding, nil, eventType, reason, action, note, args...)
	}
}

func (c *Controller) recordBGPServerStarted(policy *v1alpha1.BGPPolicy, routerID string, localASN, listenPort int32) {
	c.eventRecorder.eventf(policy, corev1.EventTypeNormal, reasonBGPServerStarted, actionApplyBGPPolicy,
		"Started the BGP server on Node %s with router ID %s, local ASN %d and listen port %d",
		c.nodeName, routerID, localASN, listenPort)
}

// recordSyncEvents records the Events that the result of a sync implies. The caller must hold bgpPolicyStateMutex.
func (c *Controller) recordSyncEvents(effectivePolicy *v1alpha1.BGPPolicy, err error) {
	// Without a BGPPolicy that selects the Node, there is no object to record an Event on.
	if effectivePolicy == nil {
		return
	}
	if err != nil {
		reason := reasonBGPPolicySyncFailed
		var stepErr *syncStepError
		if errors.As(err, &stepErr) {
			reason = stepErr.reason
		}
		c.eventRecorder.eventf(effectivePolicy, corev1.EventTypeWarning, reason, actionApplyBGPPolicy,
			"Failed to apply the BGPPolicy on Node %s: %v", c.nodeName, err)
	}
	allPolicies, listErr := c.bgpPolicyLister.List(labels.Everything())
	if listErr != nil {
		klog.ErrorS(listErr, "Failed to list BGPPolicies")
		return
	}
	for _, policy := range allPolicies {
		if policy.Name != effectivePolicy.Name && c.matchesCurrentNode(policy) {
			c.eventRecorder.eventf(policy, corev1.EventTypeNormal, reasonBGPPolicyNotEffective, actionApplyBGPPolicy,
				"Not applied on Node %s, which applies the older BGPPolicy %s", c.nodeName, effectivePolicy.Name)
		}
	}
}

// recordPeerSessionEvent records an Event on a BGPPolicy when the BGP session with one of its peers reaches the
// Established state or leaves it. prePeer is nil when the previous poll did not see the peer.
func (c *Controller) recordPeerSessionEvent(policyName string, prePeer *bgp.PeerStatus, curPeer bgp.PeerStatus) {
	wasEstablished := prePeer != nil && prePeer.SessionState == bgp.SessionEstablished
	isEstablished := curPeer.SessionState == bgp.SessionEstablished
	if wasEstablished == isEstablished {
		return
	}
	policy, err := c.bgpPolicyLister.Get(policyName)
	if err != nil {
		// The BGPPolicy has just been deleted, so there is no object to record the Event on.
		klog.V(2).InfoS("Not recording the Event for a BGP session, as its BGPPolicy was not found", "BGPPolicy", policyName, "err", err)
		return
	}
	switch {
	case isEstablished && prePeer == nil:
		c.eventRecorder.eventf(policy, corev1.EventTypeNormal, reasonBGPPeerUp, actionMonitorBGPPeer,
			"BGP session with peer %s (ASN %d) is Established on Node %s",
			curPeer.Address, curPeer.ASN, c.nodeName)
	case isEstablished:
		c.eventRecorder.eventf(policy, corev1.EventTypeNormal, reasonBGPPeerUp, actionMonitorBGPPeer,
			"BGP session with peer %s (ASN %d) is Established on Node %s, previous state %s",
			curPeer.Address, curPeer.ASN, c.nodeName, prePeer.SessionState)
	default:
		c.eventRecorder.eventf(policy, corev1.EventTypeWarning, reasonBGPPeerDown, actionMonitorBGPPeer,
			"BGP session with peer %s (ASN %d) is no longer Established on Node %s, current state %s",
			curPeer.Address, curPeer.ASN, c.nodeName, curPeer.SessionState)
	}
}
