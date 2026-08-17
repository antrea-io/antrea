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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	testingclock "k8s.io/utils/clock/testing"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

const testUser = "alice"

var testUserInfo = &user.DefaultInfo{Name: testUser, Groups: []string{"network-ops"}}

// fakeAuthorizer answers checks from a fixed set of grants and records everything it was asked,
// so that a test can assert both the decision reached and how many SubjectAccessReviews it took.
//
// Authorize runs on GetFlows's own goroutine, so a test that revokes or grants a key while a
// stream is running concurrently (as one recheck does, to simulate a grant changing mid-stream)
// must go through grant/revoke/breakCheck rather than touching allowed/failing directly: mu is
// what makes that safe under the race detector.
type fakeAuthorizer struct {
	mu      sync.Mutex
	allowed sets.Set[string]
	failing sets.Set[string]
	calls   []string
	attrs   []authorizer.Attributes
}

func newFakeAuthorizer(allowed ...string) *fakeAuthorizer {
	return &fakeAuthorizer{allowed: sets.New(allowed...), failing: sets.New[string]()}
}

func (f *fakeAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := attributesKey(attrs)
	f.calls = append(f.calls, key)
	f.attrs = append(f.attrs, attrs)
	if f.failing.Has(key) {
		return authorizer.DecisionNoOpinion, "", errors.New("connection refused")
	}
	if f.allowed.Has(key) {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionNoOpinion, "no grant", nil
}

// grant makes key pass authorization from this point on.
func (f *fakeAuthorizer) grant(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed.Insert(key)
}

// revoke makes key fail authorization from this point on.
func (f *fakeAuthorizer) revoke(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed.Delete(key)
}

// breakCheck makes checking key return an error, as if the API server were unreachable, from this
// point on.
func (f *fakeAuthorizer) breakCheck(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing.Insert(key)
}

// attributesKey renders one check the way the tests below name grants.
func attributesKey(attrs authorizer.Attributes) string {
	resource := attrs.GetResource()
	if subresource := attrs.GetSubresource(); subresource != "" {
		resource += "/" + subresource
	}
	scope := attrs.GetNamespace()
	if scope == "" {
		scope = clusterScope
	}
	return fmt.Sprintf("%s %s %s.%s in %s", attrs.GetUser().GetName(), attrs.GetVerb(), resource, attrs.GetAPIGroup(), scope)
}

// flowsGrant names the grant that lets testUser stream flows in a Namespace, or cluster-wide when
// namespace is empty.
func flowsGrant(verb, namespace string) string {
	scope := namespace
	if scope == "" {
		scope = clusterScope
	}
	return fmt.Sprintf("%s %s %s.%s in %s", testUser, verb, flowResource, flowAPIGroup, scope)
}

// identityGrant names the grant that lets testUser identify endpoints in a Namespace.
func identityGrant(namespace string) string {
	return fmt.Sprintf("%s %s %s/%s.%s in %s", testUser, getVerb, flowResource, identitySubresource, flowAPIGroup, namespace)
}

func newTestAuthorizer(delegate authorizer.Authorizer) (*Authorizer, *testingclock.FakeClock) {
	fakeClock := testingclock.NewFakeClock(time.Now())
	return newAuthorizer(delegate, fakeClock), fakeClock
}

func TestNewStreamAuthorization_Scope(t *testing.T) {
	tests := []struct {
		name        string
		req         *flowpb.GetFlowsRequest
		grants      []string
		wantCode    codes.Code
		wantErrMsg  string
		wantCalls   []string
		wantCluster bool
		wantNS      []string
	}{
		{
			name:        "cluster scope allowed",
			req:         &flowpb.GetFlowsRequest{ClusterWide: true, Follow: true},
			grants:      []string{flowsGrant(watchVerb, "")},
			wantCalls:   []string{flowsGrant(watchVerb, "")},
			wantCluster: true,
		},
		{
			name:       "cluster scope denied",
			req:        &flowpb.GetFlowsRequest{ClusterWide: true, Follow: true},
			wantCode:   codes.PermissionDenied,
			wantErrMsg: "cluster-wide",
			wantCalls:  []string{flowsGrant(watchVerb, "")},
		},
		{
			name:      "the requested namespace is allowed",
			req:       &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			grants:    []string{flowsGrant(watchVerb, "ns-a")},
			wantCalls: []string{flowsGrant(watchVerb, "ns-a")},
			wantNS:    []string{"ns-a"},
		},
		{
			name:       "the requested namespace denied rejects the request",
			req:        &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			wantCode:   codes.PermissionDenied,
			wantErrMsg: "namespace ns-a",
			wantCalls:  []string{flowsGrant(watchVerb, "ns-a")},
		},
		{
			name:   "a non-follow stream is authorized with list",
			req:    &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}},
			grants: []string{flowsGrant(listVerb, "ns-a")},
			// A "watch" grant does not cover a "list" request, and vice versa: granting only
			// "list" is how an admin gives history-only access.
			wantCalls: []string{flowsGrant(listVerb, "ns-a")},
			wantNS:    []string{"ns-a"},
		},
		{
			name:       "a watch grant does not authorize a list request",
			req:        &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}},
			grants:     []string{flowsGrant(watchVerb, "ns-a")},
			wantCode:   codes.PermissionDenied,
			wantErrMsg: "not allowed to list",
		},
		{
			// The cap is enforced on the raw list, before deduplication, so repeating a namespace
			// does not let a client work around it.
			name:       "a duplicate namespace still counts toward the request length cap",
			req:        &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a", "ns-a"}, Follow: true},
			wantCode:   codes.InvalidArgument,
			wantErrMsg: fmt.Sprintf("at most %d namespaces", maxRequestedNamespaces),
		},
		{
			name:       "an empty scope is rejected rather than defaulted",
			req:        &flowpb.GetFlowsRequest{Follow: true},
			wantCode:   codes.InvalidArgument,
			wantErrMsg: "name the namespaces",
		},
		{
			name:       "namespaces and cluster_wide are mutually exclusive",
			req:        &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, ClusterWide: true},
			wantCode:   codes.InvalidArgument,
			wantErrMsg: "mutually exclusive",
		},
		{
			name:       "an empty namespace name is rejected",
			req:        &flowpb.GetFlowsRequest{Namespaces: []string{""}},
			wantCode:   codes.InvalidArgument,
			wantErrMsg: "empty name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeAuthorizer(tt.grants...)
			a, _ := newTestAuthorizer(fake)

			sa, err := a.NewStreamAuthorization(context.Background(), testUserInfo, tt.req)

			if tt.wantCode != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, status.Code(err))
				assert.Contains(t, status.Convert(err).Message(), tt.wantErrMsg)
				assert.Nil(t, sa)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantCluster, sa.StreamInfo().GetClusterWide())
				assert.Equal(t, tt.wantNS, sa.StreamInfo().GetAuthorizedNamespaces())
			}
			if tt.wantCalls != nil {
				assert.Equal(t, tt.wantCalls, fake.calls)
			}
		})
	}
}

func TestNewStreamAuthorization_TooManyNamespaces(t *testing.T) {
	namespaces := make([]string, maxRequestedNamespaces+1)
	for i := range namespaces {
		namespaces[i] = fmt.Sprintf("ns-%d", i)
	}
	fake := newFakeAuthorizer()
	a, _ := newTestAuthorizer(fake)

	_, err := a.NewStreamAuthorization(context.Background(), testUserInfo, &flowpb.GetFlowsRequest{Namespaces: namespaces})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), fmt.Sprintf("at most %d namespaces", maxRequestedNamespaces))
	// The request is rejected before any SubjectAccessReview, so a client cannot use an
	// over-long list to fan out onto the API server.
	assert.Empty(t, fake.calls)
}

// TestNewStreamAuthorization_FailsClosed covers the case where the authorization decision itself
// cannot be reached: a new stream must not open while the API server is unreachable.
func TestNewStreamAuthorization_FailsClosed(t *testing.T) {
	for _, tt := range []struct {
		name string
		req  *flowpb.GetFlowsRequest
		fail string
	}{
		{
			name: "namespace scope",
			req:  &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			fail: flowsGrant(watchVerb, "ns-a"),
		},
		{
			name: "cluster scope",
			req:  &flowpb.GetFlowsRequest{ClusterWide: true, Follow: true},
			fail: flowsGrant(watchVerb, ""),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeAuthorizer(tt.fail)
			fake.breakCheck(tt.fail)
			a, _ := newTestAuthorizer(fake)

			sa, err := a.NewStreamAuthorization(context.Background(), testUserInfo, tt.req)

			require.Error(t, err)
			assert.Equal(t, codes.Unavailable, status.Code(err))
			assert.Nil(t, sa)
		})
	}
}

// TestNewStreamAuthorization_Attributes pins down the SubjectAccessReview an admin actually has to
// satisfy, since the whole design rests on those attributes being the ones a Role can name.
func TestNewStreamAuthorization_Attributes(t *testing.T) {
	fake := newFakeAuthorizer(flowsGrant(watchVerb, "ns-a"))
	a, _ := newTestAuthorizer(fake)

	_, err := a.NewStreamAuthorization(context.Background(), testUserInfo, &flowpb.GetFlowsRequest{
		Namespaces: []string{"ns-a"},
		Follow:     true,
	})
	require.NoError(t, err)

	require.Len(t, fake.attrs, 1)
	attrs := fake.attrs[0]
	assert.Equal(t, "observability.antrea.io", attrs.GetAPIGroup())
	assert.Equal(t, "flows", attrs.GetResource())
	assert.Empty(t, attrs.GetSubresource())
	assert.Equal(t, "watch", attrs.GetVerb())
	assert.Equal(t, "ns-a", attrs.GetNamespace())
	assert.True(t, attrs.IsResourceRequest())
	assert.Equal(t, testUser, attrs.GetUser().GetName())
	// The groups must reach the SubjectAccessReview, or a Group-bound Role never applies.
	assert.Equal(t, []string{"network-ops"}, attrs.GetUser().GetGroups())
}

func TestRevalidate(t *testing.T) {
	newStream := func(t *testing.T, fake *fakeAuthorizer, req *flowpb.GetFlowsRequest) (*StreamAuthorization, *testingclock.FakeClock) {
		t.Helper()
		a, fakeClock := newTestAuthorizer(fake)
		sa, err := a.NewStreamAuthorization(context.Background(), testUserInfo, req)
		require.NoError(t, err)
		fake.calls = nil
		return sa, fakeClock
	}
	namespaceReq := &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true}
	namespaceGrants := []string{flowsGrant(watchVerb, "ns-a")}

	t.Run("does nothing before the revalidation interval", func(t *testing.T) {
		fake := newFakeAuthorizer(namespaceGrants...)
		sa, fakeClock := newStream(t, fake, namespaceReq)

		fakeClock.Step(revalidationInterval - time.Second)
		require.NoError(t, sa.Revalidate(context.Background()))
		assert.Empty(t, fake.calls)
	})

	t.Run("re-checks the scope after the revalidation interval", func(t *testing.T) {
		fake := newFakeAuthorizer(namespaceGrants...)
		sa, fakeClock := newStream(t, fake, namespaceReq)

		fakeClock.Step(revalidationInterval)
		require.NoError(t, sa.Revalidate(context.Background()))
		assert.Equal(t, namespaceGrants, fake.calls)

		// And not again until the next interval.
		fake.calls = nil
		require.NoError(t, sa.Revalidate(context.Background()))
		assert.Empty(t, fake.calls)
	})

	t.Run("ends the stream when a grant is revoked", func(t *testing.T) {
		fake := newFakeAuthorizer(namespaceGrants...)
		sa, fakeClock := newStream(t, fake, namespaceReq)

		fake.revoke(flowsGrant(watchVerb, "ns-a"))
		fakeClock.Step(revalidationInterval)
		err := sa.Revalidate(context.Background())

		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "namespace(s) ns-a was revoked")
	})

	t.Run("ends a cluster-wide stream when its grant is revoked", func(t *testing.T) {
		fake := newFakeAuthorizer(flowsGrant(watchVerb, ""))
		sa, fakeClock := newStream(t, fake, &flowpb.GetFlowsRequest{ClusterWide: true, Follow: true})

		fake.revoke(flowsGrant(watchVerb, ""))
		fakeClock.Step(revalidationInterval)
		err := sa.Revalidate(context.Background())

		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "cluster-wide was revoked")
	})

	t.Run("keeps the stream open when a check fails", func(t *testing.T) {
		fake := newFakeAuthorizer(namespaceGrants...)
		sa, fakeClock := newStream(t, fake, namespaceReq)

		// Fail closed on open, fail open on refresh: an established stream survives a
		// control-plane blip.
		fake.breakCheck(flowsGrant(watchVerb, "ns-a"))
		fakeClock.Step(revalidationInterval)
		assert.NoError(t, sa.Revalidate(context.Background()))
	})
}

// podFlow builds a Pod-to-Pod record between two Namespaces.
func podFlow(sourceNamespace, destinationNamespace string) *flowpb.Flow {
	return &flowpb.Flow{
		Id: sourceNamespace + "->" + destinationNamespace,
		K8S: &flowpb.Kubernetes{
			SourcePodNamespace:      sourceNamespace,
			SourcePodName:           "source-pod",
			DestinationPodNamespace: destinationNamespace,
			DestinationPodName:      "destination-pod",
		},
	}
}

func TestAuthorize_RecordVisibility(t *testing.T) {
	tests := []struct {
		name        string
		req         *flowpb.GetFlowsRequest
		grants      []string
		flows       []*flowpb.Flow
		wantIDs     []string
		wantSrcTier flowpb.EndpointDisclosure
		wantDstTier flowpb.EndpointDisclosure
	}{
		{
			name:    "a cluster-wide stream observes everything untouched",
			req:     &flowpb.GetFlowsRequest{ClusterWide: true, Follow: true},
			grants:  []string{flowsGrant(watchVerb, "")},
			flows:   []*flowpb.Flow{podFlow("ns-a", "ns-b"), podFlow("ns-c", "ns-d"), {Id: "no-k8s"}},
			wantIDs: []string{"ns-a->ns-b", "ns-c->ns-d", "no-k8s"},
		},
		{
			name:    "both endpoints in scope",
			req:     &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			grants:  []string{flowsGrant(watchVerb, "ns-a")},
			flows:   []*flowpb.Flow{podFlow("ns-a", "ns-a")},
			wantIDs: []string{"ns-a->ns-a"},
		},
		{
			name:    "neither endpoint in scope",
			req:     &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			grants:  []string{flowsGrant(watchVerb, "ns-a")},
			flows:   []*flowpb.Flow{podFlow("ns-b", "ns-c"), {Id: "no-k8s"}},
			wantIDs: nil,
		},
		{
			name:        "the peer is identifiable when identity is granted there",
			req:         &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			grants:      []string{flowsGrant(watchVerb, "ns-a"), identityGrant("ns-b")},
			flows:       []*flowpb.Flow{podFlow("ns-a", "ns-b")},
			wantIDs:     []string{"ns-a->ns-b"},
			wantDstTier: flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY,
		},
		{
			name:        "the peer is unidentified otherwise",
			req:         &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			grants:      []string{flowsGrant(watchVerb, "ns-a")},
			flows:       []*flowpb.Flow{podFlow("ns-a", "ns-b")},
			wantIDs:     []string{"ns-a->ns-b"},
			wantDstTier: flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW,
		},
		{
			name:        "an inbound flow from a namespace out of scope is observable",
			req:         &flowpb.GetFlowsRequest{Namespaces: []string{"ns-b"}, Follow: true},
			grants:      []string{flowsGrant(watchVerb, "ns-b")},
			flows:       []*flowpb.Flow{podFlow("ns-a", "ns-b")},
			wantIDs:     []string{"ns-a->ns-b"},
			wantSrcTier: flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW,
		},
		{
			name:   "an external endpoint is unidentified",
			req:    &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			grants: []string{flowsGrant(watchVerb, "ns-a")},
			flows: []*flowpb.Flow{{
				Id: "external->ns-a",
				K8S: &flowpb.Kubernetes{
					FlowType:                flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
					DestinationPodNamespace: "ns-a",
				},
			}},
			wantIDs:     []string{"external->ns-a"},
			wantSrcTier: flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeAuthorizer(tt.grants...)
			a, _ := newTestAuthorizer(fake)
			sa, err := a.NewStreamAuthorization(context.Background(), testUserInfo, tt.req)
			require.NoError(t, err)

			got := sa.Authorize(context.Background(), tt.flows)

			gotIDs := make([]string, 0, len(got))
			for _, f := range got {
				gotIDs = append(gotIDs, f.GetId())
				assert.Equal(t, tt.wantSrcTier, f.GetK8S().GetSourceDisclosure(), "source disclosure of %s", f.GetId())
				assert.Equal(t, tt.wantDstTier, f.GetK8S().GetDestinationDisclosure(), "destination disclosure of %s", f.GetId())
			}
			if tt.wantIDs == nil {
				assert.Empty(t, gotIDs)
			} else {
				assert.Equal(t, tt.wantIDs, gotIDs)
			}
		})
	}
}

// TestAuthorize_LeavesTheRecordUntouched guards the invariant that makes redaction safe at all: a
// record belongs to the ring buffer and is broadcast to every other stream, so redacting it for one
// client must not alter what another sees.
func TestAuthorize_LeavesTheRecordUntouched(t *testing.T) {
	fake := newFakeAuthorizer(flowsGrant(watchVerb, "ns-a"))
	a, _ := newTestAuthorizer(fake)
	sa, err := a.NewStreamAuthorization(context.Background(), testUserInfo, &flowpb.GetFlowsRequest{
		Namespaces: []string{"ns-a"},
		Follow:     true,
	})
	require.NoError(t, err)

	original := podFlow("ns-a", "ns-b")
	got := sa.Authorize(context.Background(), []*flowpb.Flow{original})

	require.Len(t, got, 1)
	assert.NotSame(t, original, got[0])
	assert.Empty(t, got[0].GetK8S().GetDestinationPodName())
	assert.Equal(t, "destination-pod", original.GetK8S().GetDestinationPodName())
	assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_UNSPECIFIED, original.GetK8S().GetDestinationDisclosure())
}

// TestAuthorize_ReturnsTheRecordWhenNothingIsWithheld pins down that the common case allocates
// nothing: the record itself is streamed, not a copy of it.
func TestAuthorize_ReturnsTheRecordWhenNothingIsWithheld(t *testing.T) {
	for _, tt := range []struct {
		name   string
		req    *flowpb.GetFlowsRequest
		grants []string
		flow   *flowpb.Flow
	}{
		{
			name:   "cluster-wide",
			req:    &flowpb.GetFlowsRequest{ClusterWide: true, Follow: true},
			grants: []string{flowsGrant(watchVerb, "")},
			flow:   podFlow("ns-a", "ns-b"),
		},
		{
			name:   "both endpoints in scope",
			req:    &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true},
			grants: []string{flowsGrant(watchVerb, "ns-a")},
			flow:   podFlow("ns-a", "ns-a"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeAuthorizer(tt.grants...)
			a, _ := newTestAuthorizer(fake)
			sa, err := a.NewStreamAuthorization(context.Background(), testUserInfo, tt.req)
			require.NoError(t, err)

			got := sa.Authorize(context.Background(), []*flowpb.Flow{tt.flow})

			require.Len(t, got, 1)
			assert.Same(t, tt.flow, got[0])
		})
	}
}

func TestAuthorize_IdentityChecks(t *testing.T) {
	newStream := func(t *testing.T, fake *fakeAuthorizer) (*StreamAuthorization, *testingclock.FakeClock) {
		t.Helper()
		a, fakeClock := newTestAuthorizer(fake)
		sa, err := a.NewStreamAuthorization(context.Background(), testUserInfo, &flowpb.GetFlowsRequest{
			Namespaces: []string{"ns-a"},
			Follow:     true,
		})
		require.NoError(t, err)
		fake.calls = nil
		return sa, fakeClock
	}
	// destinationTier reports how the peer of a single ns-a -> ns-b record was disclosed.
	destinationTier := func(t *testing.T, sa *StreamAuthorization) flowpb.EndpointDisclosure {
		t.Helper()
		got := sa.Authorize(context.Background(), []*flowpb.Flow{podFlow("ns-a", "ns-b")})
		require.Len(t, got, 1)
		return got[0].GetK8S().GetDestinationDisclosure()
	}

	t.Run("a namespace is checked once and then memoized", func(t *testing.T) {
		fake := newFakeAuthorizer(flowsGrant(watchVerb, "ns-a"), identityGrant("ns-b"))
		sa, _ := newStream(t, fake)

		flows := []*flowpb.Flow{podFlow("ns-a", "ns-b"), podFlow("ns-a", "ns-b"), podFlow("ns-a", "ns-b")}
		require.Len(t, sa.Authorize(context.Background(), flows), 3)

		assert.Equal(t, []string{identityGrant("ns-b")}, fake.calls)
	})

	t.Run("an endpoint in the authorized set costs no check", func(t *testing.T) {
		fake := newFakeAuthorizer(flowsGrant(watchVerb, "ns-a"))
		sa, _ := newStream(t, fake)

		got := sa.Authorize(context.Background(), []*flowpb.Flow{podFlow("ns-a", "ns-a")})

		require.Len(t, got, 1)
		assert.Empty(t, fake.calls)
	})

	t.Run("a memoized decision is re-checked after the revalidation interval", func(t *testing.T) {
		fake := newFakeAuthorizer(flowsGrant(watchVerb, "ns-a"))
		sa, fakeClock := newStream(t, fake)

		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, destinationTier(t, sa))

		// Granting identity mid-stream takes effect on the next re-check. The cache expires an
		// entry strictly after its ttl elapses, so the step must clear revalidationInterval, not
		// just reach it.
		fake.grant(identityGrant("ns-b"))
		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, destinationTier(t, sa))
		fakeClock.Step(revalidationInterval + time.Nanosecond)
		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY, destinationTier(t, sa))

		// And revoking it likewise.
		fake.revoke(identityGrant("ns-b"))
		fakeClock.Step(revalidationInterval + time.Nanosecond)
		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, destinationTier(t, sa))
	})

	t.Run("a failing check leaves the endpoint unidentified without repeating", func(t *testing.T) {
		fake := newFakeAuthorizer(flowsGrant(watchVerb, "ns-a"), identityGrant("ns-b"))
		fake.breakCheck(identityGrant("ns-b"))
		sa, _ := newStream(t, fake)

		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, destinationTier(t, sa))
		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, destinationTier(t, sa))
		assert.Equal(t, []string{identityGrant("ns-b")}, fake.calls)
	})

	t.Run("distinct namespaces are bounded by an LRU cache, not permanently denied", func(t *testing.T) {
		fake := newFakeAuthorizer(flowsGrant(watchVerb, "ns-a"))
		sa, _ := newStream(t, fake)

		// Every distinct peer Namespace is checked, however many are seen: past the cache's
		// capacity, the least recently asked about entry is evicted to make room, not refused a
		// check, so a stream cannot get permanently stuck denying a Namespace on the strength of
		// how much unrelated traffic it happened to see first.
		flows := make([]*flowpb.Flow, 0, maxIdentityNamespacesPerStream+10)
		for i := range maxIdentityNamespacesPerStream + 10 {
			flows = append(flows, podFlow("ns-a", fmt.Sprintf("peer-%d", i)))
		}
		got := sa.Authorize(context.Background(), flows)
		require.Len(t, got, len(flows))
		assert.Len(t, fake.calls, len(flows))
		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, got[0].GetK8S().GetDestinationDisclosure())

		// peer-0 was the least recently asked about entry once the cache filled up, so it was
		// evicted; asking about it again re-checks from scratch instead of replaying the stale
		// decision, and this time it resolves as granted.
		fake.calls = nil
		fake.grant(identityGrant("peer-0"))
		got = sa.Authorize(context.Background(), []*flowpb.Flow{podFlow("ns-a", "peer-0")})
		require.Len(t, got, 1)
		assert.Equal(t, []string{identityGrant("peer-0")}, fake.calls)
		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY, got[0].GetK8S().GetDestinationDisclosure())
	})
}
