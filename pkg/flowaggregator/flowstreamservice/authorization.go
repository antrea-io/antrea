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

package flowstreamservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/options"
	authorizationv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

const (
	// flowAPIGroup, flowResource and identitySubresource name the virtual resources that
	// FlowStreamService authorizes against: "flows.observability.antrea.io" for flow
	// visibility, and its "identity" subresource for endpoint identity disclosure.
	flowAPIGroup        = "observability.antrea.io"
	flowResource        = "flows"
	identitySubresource = "identity"

	// listVerb authorizes a non-follow stream (drain what the ring buffer holds, then close) and
	// watchVerb a follow stream (history, then a live tap), so that granting only "list" yields
	// history-only access. "create" is deliberately not used.
	listVerb  = "list"
	watchVerb = "watch"
	// getVerb authorizes identity disclosure, which is a read of one endpoint's identity rather
	// than a stream of anything.
	getVerb = "get"

	// authorizationCacheTTL is how long an authorization decision, allow or deny, is cached and
	// therefore how long revoking a grant can take to be noticed. It is deliberately as long as
	// the shortest lifetime Kubernetes gives a projected ServiceAccount token, since a client
	// whose credential is rotated that often cannot hold a stream open past it anyway.
	authorizationCacheTTL = 10 * time.Minute
	// revalidationInterval is how often an established stream re-checks its own scope. It is
	// much shorter than authorizationCacheTTL, so nearly every check is served from the
	// authorizer's cache and the actual revocation latency is set by that TTL rather than by
	// this interval.
	revalidationInterval = time.Minute

	// maxRequestedNamespaces caps how many Namespaces one request may contain, bounding the burst
	// of SubjectAccessReviews opening a stream can cost. It is currently set to a single namespace
	// because antrea-ui restricts a non-cluster-scope user to pick a single namespace to observe
	// flows. If this changes in the future, we can set the value to be greater than one.
	maxRequestedNamespaces = 1
	// maxIdentityNamespacesPerStream bounds the size of one stream's own identity-decision cache.
	// Unlike maxRequestedNamespaces, these Namespaces are discovered from traffic rather than named
	// by the client, so a client cannot stay under this by asking for less. It is not what protects
	// kube-apiserver from a stream fanning out across many distinct Namespaces: the delegating
	// authorizer underneath already caches every SubjectAccessReview it makes, in its own
	// process-wide LRU (8192 entries, 10-minute TTL, shared across every stream and every subject),
	// so a Namespace evicted here for being the least recently seen still resolves from that shared
	// cache rather than costing a fresh round trip, unless it has also fallen out of it. This bound
	// only keeps a single long-lived stream's own bookkeeping from growing without limit.
	maxIdentityNamespacesPerStream = 250

	// identityCheckTimeout bounds a single flows/identity SubjectAccessReview, including the
	// delegating authorizer's own retries. canIdentify runs on the record dispatch path, once per
	// newly-seen peer Namespace per stream: without a bound, a slow or unreachable API server would
	// retry with backoff for several seconds on that path, stalling every record behind it in the
	// same batch and starving the ring buffer consumer, which the buffer then sees as a slow reader.
	// canIdentify already fails closed on any error, so timing out here is indistinguishable to it
	// from any other authorization failure.
	identityCheckTimeout = 2 * time.Second

	// clusterScope is how the cluster-wide scope is named in messages to the client. A
	// SubjectAccessReview with an empty Namespace is a cluster-scoped check, which no
	// namespace-scoped RoleBinding can satisfy.
	clusterScope = "cluster-wide"
)

// Authorizer decides what an authenticated FlowStreamService client may observe, by asking
// Kubernetes RBAC about the virtual "flows" resource. It is shared by every stream: the
// underlying delegating authorizer caches decisions for authorizationCacheTTL, keyed by the full
// SubjectAccessReview spec (so by user, UID, groups and extra as well as by the resource
// attributes), which is what keeps concurrent streams for the same subject from each paying for
// their own round-trips.
type Authorizer struct {
	delegate authorizer.Authorizer
	clock    clock.Clock
}

// NewAuthorizer builds an Authorizer that resolves permissions with SubjectAccessReviews against
// the Kubernetes API server. The Flow Aggregator's ServiceAccount is already bound to
// system:auth-delegator, which grants creating them.
func NewAuthorizer(client authorizationv1client.AuthorizationV1Interface) (*Authorizer, error) {
	delegate, err := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		AllowCacheTTL:             authorizationCacheTTL,
		DenyCacheTTL:              authorizationCacheTTL,
		WebhookRetryBackoff:       options.DefaultAuthWebhookRetryBackoff(),
	}.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create delegating authorizer: %w", err)
	}
	return newAuthorizer(delegate, clock.RealClock{}), nil
}

// newAuthorizer is the constructor shared with the tests, which substitute both the authorization
// decisions and the clock.
func newAuthorizer(delegate authorizer.Authorizer, clock clock.Clock) *Authorizer {
	return &Authorizer{delegate: delegate, clock: clock}
}

// allowed reports whether user holds verb on the virtual flow resource (or on its identity
// subresource) in namespace. An empty namespace is a cluster-scoped check.
func (a *Authorizer) allowed(ctx context.Context, u user.Info, verb, subresource, namespace string) (bool, error) {
	decision, reason, err := a.delegate.Authorize(ctx, authorizer.AttributesRecord{
		User:            u,
		Verb:            verb,
		APIGroup:        flowAPIGroup,
		Resource:        flowResource,
		Subresource:     subresource,
		Namespace:       namespace,
		ResourceRequest: true,
	})
	if err != nil {
		return false, fmt.Errorf("SubjectAccessReview failed: %w", err)
	}
	if decision != authorizer.DecisionAllow {
		klog.V(4).InfoS("FlowStreamService authorization denied",
			"user", u.GetName(), "verb", verb, "resource", flowResource, "subresource", subresource, "namespace", namespace, "reason", reason)
		return false, nil
	}
	return true, nil
}

// StreamAuthorization is one stream's authorization state: the scope it was opened with, and the
// endpoint-identity decisions discovered while it runs. It is used from the single goroutine
// serving that stream and is not safe for concurrent use.
type StreamAuthorization struct {
	authorizer *Authorizer
	user       user.Info
	// verb is the one this stream was authorized with, and the one revalidation re-checks:
	// watchVerb for a follow stream, listVerb otherwise.
	verb string
	// clusterWide is set when the client asked for, and was granted, visibility of the whole
	// cluster. Such a stream observes every record with nothing redacted, so none of the fields
	// below are used.
	clusterWide bool
	// namespaces is the authorized set: the Namespaces the client named and was allowed to
	// observe. Because a partially-denied request is rejected outright, it is either every
	// Namespace the client named or the stream does not exist.
	namespaces sets.Set[string]
	// orderedNamespaces holds the same Namespaces in the order the client named them, only so
	// that they can be reported back unshuffled.
	orderedNamespaces []string
	// lastRevalidated is when the scope was last confirmed, either at stream open or by
	// Revalidate.
	lastRevalidated time.Time
	// identity caches flows/identity decisions for Namespaces outside the authorized set, so
	// that the same peer Namespace is not re-checked for every record. Entries expire after
	// revalidationInterval, which normally costs nothing because the Authorizer's own cache
	// answers the re-check, and the cache evicts its least recently seen entry once it holds
	// maxIdentityNamespacesPerStream of them, rather than refusing to track any Namespace beyond
	// that count for the rest of the stream's lifetime.
	identity *cache.LRUExpireCache
}

// NewStreamAuthorization validates the scope of a GetFlows request and authorizes it, returning
// the state the stream needs to authorize the records it goes on to send.
//
// Authorization fails closed here: a client cannot open a stream while the API server is
// unreachable, and a request naming any Namespace the client may not observe is rejected in full,
// rather than being silently narrowed to the ones it may.
//
// The checks stop at the first Namespace that is denied, and only that one is named back to the
// client. Reporting every denied Namespace at once would be friendlier, but it would let a client
// holding a single Namespace spend a SubjectAccessReview on each of the maxRequestedNamespaces
// Namespaces it names; stopping early bounds one request to the grants the client actually holds,
// plus the one that ended it.
//
// The returned errors are gRPC status errors, ready to be returned from GetFlows: what a client is
// told about its own request is part of this decision, so it is worth keeping in one place.
func (a *Authorizer) NewStreamAuthorization(ctx context.Context, u user.Info, req *flowpb.GetFlowsRequest) (*StreamAuthorization, error) {
	verb := listVerb
	if req.GetFollow() {
		verb = watchVerb
	}
	sa := &StreamAuthorization{
		authorizer:      a,
		user:            u,
		verb:            verb,
		clusterWide:     req.GetClusterWide(),
		lastRevalidated: a.clock.Now(),
		identity:        cache.NewLRUExpireCacheWithClock(maxIdentityNamespacesPerStream, a.clock),
	}

	requested, err := requestedNamespaces(req)
	if err != nil {
		return nil, err
	}

	if sa.clusterWide {
		allowed, err := a.allowed(ctx, u, verb, "", "")
		if err != nil {
			klog.ErrorS(err, "Failed to authorize FlowStreamService client", "user", u.GetName(), "scope", clusterScope)
			return nil, status.Error(codes.Unavailable, "authorization is unavailable, retry later")
		}
		if !allowed {
			return nil, status.Errorf(codes.PermissionDenied, "not allowed to %s %s.%s cluster-wide", verb, flowResource, flowAPIGroup)
		}
		return sa, nil
	}

	for _, ns := range requested {
		allowed, err := a.allowed(ctx, u, verb, "", ns)
		if err != nil {
			klog.ErrorS(err, "Failed to authorize FlowStreamService client", "user", u.GetName(), "namespace", ns)
			return nil, status.Error(codes.Unavailable, "authorization is unavailable, retry later")
		}
		if !allowed {
			return nil, status.Errorf(codes.PermissionDenied, "not allowed to %s %s.%s in namespace %s",
				verb, flowResource, flowAPIGroup, ns)
		}
	}
	sa.orderedNamespaces = requested
	sa.namespaces = sets.New(requested...)
	return sa, nil
}

// requestedNamespaces validates the scope of a request and returns the Namespaces it names,
// deduplicated and in the order they were given. It returns an empty slice for a cluster-wide
// request.
func requestedNamespaces(req *flowpb.GetFlowsRequest) ([]string, error) {
	namespaces := req.GetNamespaces()
	if req.GetClusterWide() {
		if len(namespaces) > 0 {
			return nil, status.Error(codes.InvalidArgument, "namespaces and cluster_wide are mutually exclusive")
		}
		return nil, nil
	}
	if len(namespaces) == 0 {
		// An empty scope is reserved rather than defaulted: it may come to mean "every Namespace
		// I am allowed to observe", which cannot be answered today because Kubernetes has no
		// reverse lookup from a subject to the Namespaces it may access. Defaulting it to
		// anything now would make that a breaking change later.
		return nil, status.Error(codes.InvalidArgument, "name the namespaces to observe flows in, or set cluster_wide")
	}
	if len(namespaces) > maxRequestedNamespaces {
		return nil, status.Errorf(codes.InvalidArgument, "a request may name at most %d namespaces, got %d", maxRequestedNamespaces, len(namespaces))
	}
	deduped := make([]string, 0, len(namespaces))
	seen := sets.New[string]()
	for _, ns := range namespaces {
		if ns == "" {
			// An empty Namespace in a SubjectAccessReview is a cluster-scoped check, so it must
			// never reach one from this list: cluster_wide is how cluster scope is requested.
			return nil, status.Error(codes.InvalidArgument, "namespaces must not contain an empty name")
		}
		if seen.Has(ns) {
			continue
		}
		seen.Insert(ns)
		deduped = append(deduped, ns)
	}
	return deduped, nil
}

// StreamInfo reports the scope the stream was actually opened with, to be sent to the client in
// the first response of the stream.
func (sa *StreamAuthorization) StreamInfo() *flowpb.StreamInfo {
	return &flowpb.StreamInfo{
		AuthorizedNamespaces: sa.orderedNamespaces,
		ClusterWide:          sa.clusterWide,
	}
}

// Revalidate re-checks the stream's scope, so that revoking a grant eventually ends a stream that
// is already running instead of only blocking the next one. It is cheap to call often: it does
// nothing until revalidationInterval has passed, and the checks it then makes are normally served
// from the Authorizer's cache.
//
// Unlike opening a stream, this fails open: a Namespace whose check errors keeps its previous
// decision, so an established stream survives a control-plane blip while a new one cannot open
// under false pretenses. A Namespace that is genuinely no longer authorized ends the stream — a
// client that wants the rest of its scope can reconnect without it, which is the same contract as
// naming a Namespace it may not observe in the first place.
func (sa *StreamAuthorization) Revalidate(ctx context.Context) error {
	now := sa.authorizer.clock.Now()
	if now.Sub(sa.lastRevalidated) < revalidationInterval {
		return nil
	}
	sa.lastRevalidated = now

	if sa.clusterWide {
		allowed, err := sa.authorizer.allowed(ctx, sa.user, sa.verb, "", "")
		if err != nil {
			klog.V(2).ErrorS(err, "Failed to revalidate FlowStreamService stream, keeping it open", "user", sa.user.GetName(), "scope", clusterScope)
			return nil
		}
		if !allowed {
			return status.Errorf(codes.PermissionDenied, "%s access to %s.%s cluster-wide was revoked", sa.verb, flowResource, flowAPIGroup)
		}
		return nil
	}

	var revoked []string
	for _, ns := range sa.orderedNamespaces {
		allowed, err := sa.authorizer.allowed(ctx, sa.user, sa.verb, "", ns)
		if err != nil {
			klog.V(2).ErrorS(err, "Failed to revalidate FlowStreamService stream, keeping it open", "user", sa.user.GetName(), "namespace", ns)
			continue
		}
		if !allowed {
			revoked = append(revoked, ns)
		}
	}
	if len(revoked) > 0 {
		return status.Errorf(codes.PermissionDenied, "%s access to %s.%s in namespace(s) %s was revoked",
			sa.verb, flowResource, flowAPIGroup, strings.Join(revoked, ", "))
	}
	return nil
}

// Authorize applies the stream's authorization to a batch of records, dropping the ones the
// client may not observe at all and substituting a redacted copy for the ones it may only observe
// in part.
//
// Like applyFilters, it uses the caller's slice as its own write target, so it allocates nothing
// beyond the redacted copies themselves, and the returned slice aliases flows.
func (sa *StreamAuthorization) Authorize(ctx context.Context, flows []*flowpb.Flow) []*flowpb.Flow {
	if sa.clusterWide {
		return flows
	}
	authorized := flows[:0]
	for _, f := range flows {
		if af := sa.authorizeFlow(ctx, f); af != nil {
			authorized = append(authorized, af)
		}
	}
	return authorized
}

// authorizeFlow returns the record the client is allowed to observe, or nil if the record must be
// withheld from it entirely. It returns f itself when nothing has to be redacted, and a copy
// otherwise: a record is owned by the ring buffer and broadcast to every other stream, so it must
// never be modified in place.
//
// A record is observable if either of its endpoints is in the authorized set. Requiring both would
// hide precisely the cross-namespace flows a user needs — "my egress to a service I cannot see was
// dropped" is the primary debugging case. A record with neither endpoint in the set, which
// includes every record with no Kubernetes metadata at all, is observable only cluster-wide.
//
// Each endpoint is then disclosed at its own tier, resolved independently of the other's.
func (sa *StreamAuthorization) authorizeFlow(ctx context.Context, f *flowpb.Flow) *flowpb.Flow {
	k8s := f.GetK8S()
	sourceNamespace := k8s.GetSourcePodNamespace()
	destinationNamespace := k8s.GetDestinationPodNamespace()
	sourceInScope := sa.namespaces.Has(sourceNamespace)
	destinationInScope := sa.namespaces.Has(destinationNamespace)
	if !sourceInScope && !destinationInScope {
		return nil
	}
	source := sa.tierFor(ctx, sourceNamespace, sourceInScope)
	destination := sa.tierFor(ctx, destinationNamespace, destinationInScope)
	if source == tierFull && destination == tierFull {
		return f
	}
	return redactFlow(f, source, destination)
}

// tierFor resolves how much of an endpoint in the given Namespace may be disclosed:
//
//  1. the Namespace is in the authorized set, which the caller has already established, so
//     everything the record carries for that endpoint is disclosed, at no API cost;
//  2. otherwise the client holds get on flows/identity there — one cached SubjectAccessReview —
//     so the endpoint is identifiable but its placement and policies are not;
//  3. otherwise the endpoint is unidentified.
//
// An endpoint with no Namespace at all is unidentified: there is no Namespace whose owner could
// have granted anything about it. For a genuinely external endpoint there is nothing to withhold
// anyway, and a client can tell the two apart from the flow type, which is never redacted.
func (sa *StreamAuthorization) tierFor(ctx context.Context, namespace string, inScope bool) disclosureTier {
	if inScope {
		return tierFull
	}
	if namespace == "" {
		return tierFlow
	}
	if sa.canIdentify(ctx, namespace) {
		return tierIdentity
	}
	return tierFlow
}

// canIdentify reports whether the client may identify endpoints in a Namespace it cannot observe
// flows for. Decisions are cached for the stream and expire after revalidationInterval, so that
// granting or revoking flows/identity takes effect on a running stream. The cache holds at most
// maxIdentityNamespacesPerStream entries, evicting whichever Namespace it holds that was least
// recently asked about to make room for a new one — a Namespace evicted this way is simply
// re-checked, at the same cost as one never seen before, not permanently denied.
//
// It fails closed, and caches the failure like any other denial: an endpoint is left unidentified,
// and the failing check is not repeated for every record while the API server is unavailable.
func (sa *StreamAuthorization) canIdentify(ctx context.Context, namespace string) bool {
	if allowed, ok := sa.identity.Get(namespace); ok {
		return allowed.(bool)
	}
	checkCtx, cancel := context.WithTimeout(ctx, identityCheckTimeout)
	defer cancel()
	allowed, err := sa.authorizer.allowed(checkCtx, sa.user, getVerb, identitySubresource, namespace)
	if err != nil {
		klog.V(2).ErrorS(err, "Failed to check endpoint identity disclosure, leaving the endpoint unidentified",
			"user", sa.user.GetName(), "namespace", namespace)
		allowed = false
	}
	sa.identity.Add(namespace, allowed, revalidationInterval)
	return allowed
}
