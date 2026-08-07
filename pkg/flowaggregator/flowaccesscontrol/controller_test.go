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

package flowaccesscontrol

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	crdfake "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
)

func newNamespace(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func newFlowAccessControl(name string, subjects []crdv1alpha1.FlowAccessSubject, selector *metav1.LabelSelector) *crdv1alpha1.FlowAccessControl {
	return &crdv1alpha1.FlowAccessControl{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: crdv1alpha1.FlowAccessControlSpec{
			Subjects:          subjects,
			NamespaceSelector: selector,
		},
	}
}

func userSubject(name string) crdv1alpha1.FlowAccessSubject {
	return crdv1alpha1.FlowAccessSubject{Kind: crdv1alpha1.FlowAccessSubjectKindUser, Name: name}
}

func groupSubject(name string) crdv1alpha1.FlowAccessSubject {
	return crdv1alpha1.FlowAccessSubject{Kind: crdv1alpha1.FlowAccessSubjectKindGroup, Name: name}
}

func serviceAccountSubject(namespace, name string) crdv1alpha1.FlowAccessSubject {
	return crdv1alpha1.FlowAccessSubject{
		Kind:      crdv1alpha1.FlowAccessSubjectKindServiceAccount,
		Name:      name,
		Namespace: namespace,
	}
}

func selectorForLabels(l map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: l}
}

// selectorForName builds a selector matching a single Namespace by name, which is how explicit
// Namespace names are expressed now that the API only takes a label selector.
func selectorForName(name string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{v1.LabelMetadataName: name}}
}

func TestParseNamespaceSelector(t *testing.T) {
	tests := []struct {
		name         string
		selector     *metav1.LabelSelector
		wantAllowAll bool
		// wantMatches and wantNoMatch are label sets the returned selector must, and must not,
		// match. They are only checked when wantAllowAll is false.
		wantMatches []labels.Set
		wantNoMatch []labels.Set
	}{
		{
			// The security-relevant case: null is not the same as {}. It must grant nothing, not
			// everything.
			name:        "null selector grants nothing",
			selector:    nil,
			wantNoMatch: []labels.Set{{"team": "frontend"}, {}},
		},
		{
			name:         "empty selector means allowAll",
			selector:     &metav1.LabelSelector{},
			wantAllowAll: true,
		},
		{
			name:        "matchLabels selector",
			selector:    selectorForLabels(map[string]string{"team": "frontend"}),
			wantMatches: []labels.Set{{"team": "frontend"}},
			wantNoMatch: []labels.Set{{"team": "backend"}, {}},
		},
		{
			name:        "name label selector",
			selector:    selectorForName("backend"),
			wantMatches: []labels.Set{{v1.LabelMetadataName: "backend"}},
			wantNoMatch: []labels.Set{{v1.LabelMetadataName: "frontend"}},
		},
		{
			name:        "invalid selector grants nothing",
			selector:    &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "team", Operator: "BogusOperator"}}},
			wantNoMatch: []labels.Set{{"team": "frontend"}, {}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fac := newFlowAccessControl("test", []crdv1alpha1.FlowAccessSubject{userSubject("alice")}, tt.selector)
			gotSelector, gotAllowAll := parseNamespaceSelector(fac)
			assert.Equal(t, tt.wantAllowAll, gotAllowAll)
			if tt.wantAllowAll {
				assert.Nil(t, gotSelector)
				return
			}
			require.NotNil(t, gotSelector)
			for _, l := range tt.wantMatches {
				assert.True(t, gotSelector.Matches(l), "selector should match %v", l)
			}
			for _, l := range tt.wantNoMatch {
				assert.False(t, gotSelector.Matches(l), "selector should not match %v", l)
			}
		})
	}
}

func TestSubjectStateMatches(t *testing.T) {
	// Two FlowAccessControl objects naming the same subject: their selectors are OR-ed, which is
	// why subjectState keeps a list even though each object contributes a single selector.
	byTeam, allowAll := parseNamespaceSelector(newFlowAccessControl(
		"by-team",
		[]crdv1alpha1.FlowAccessSubject{userSubject("alice")},
		selectorForLabels(map[string]string{"team": "frontend"}),
	))
	require.False(t, allowAll)
	byName, allowAll := parseNamespaceSelector(newFlowAccessControl(
		"by-name",
		[]crdv1alpha1.FlowAccessSubject{userSubject("alice")},
		selectorForName("backend"),
	))
	require.False(t, allowAll)
	state := &subjectState{selectors: []labels.Selector{byTeam, byName}}

	// Matches via the first selector.
	assert.True(t, state.matches(labels.Set{"team": "frontend"}))
	// Matches via the second (name-based) selector.
	assert.True(t, state.matches(labels.Set{v1.LabelMetadataName: "backend"}))
	// Matches neither.
	assert.False(t, state.matches(labels.Set{"team": "other"}))
	assert.False(t, state.matches(labels.Set{}))
}

// trackedSubject builds the cached state of a subject granted by objects with the given selectors,
// i.e. one that is not cluster-wide and therefore has its Namespace set maintained.
func trackedSubject(t *testing.T, selectors ...*metav1.LabelSelector) *subjectState {
	t.Helper()
	parsed := make([]labels.Selector, 0, len(selectors))
	for i, selector := range selectors {
		fac := newFlowAccessControl("test", []crdv1alpha1.FlowAccessSubject{userSubject("x")}, selector)
		s, allowAll := parseNamespaceSelector(fac)
		require.False(t, allowAll, "selector %d must not be cluster-wide", i)
		parsed = append(parsed, s)
	}
	return &subjectState{selectors: parsed, namespaces: sets.New[string]()}
}

// newTestController builds a Controller with the given index pre-loaded, for tests that exercise
// syncNamespace, removeNamespace or the checker directly without informers.
func newTestController(byUser, byGroup map[string]*subjectState) *Controller {
	c := &Controller{}
	c.index.Store(&subjectIndex{byUser: byUser, byGroup: byGroup})
	return c
}

// TestSyncNamespace exercises the incremental Namespace path directly, without informers.
func TestSyncNamespace(t *testing.T) {
	prodUser := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	// An allowAll subject has a nil namespaces set and must be skipped entirely.
	adminUser := &subjectState{allowAll: true}
	// A deliberately inconsistent subject: allowAll (so a nil namespaces set) but carrying a
	// selector that matches. syncFlowAccessControls never produces this, but if the allowAll guard
	// in patchNamespace were dropped, this subject would take the Insert branch and panic with
	// "assignment to entry in nil map". This pins that guard.
	inconsistentUser := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	inconsistentUser.allowAll = true
	inconsistentUser.namespaces = nil
	prodGroup := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))

	c := newTestController(
		map[string]*subjectState{
			"prod-user":    prodUser,
			"admin":        adminUser,
			"inconsistent": inconsistentUser,
		},
		map[string]*subjectState{"prod-group": prodGroup},
	)

	// A matching Namespace is added, for both User and Group subjects. syncNamespace publishes a
	// new index rather than mutating prodUser/prodGroup in place, so assertions read back through
	// the index instead of the original variables.
	c.syncNamespace(newNamespace("prod", map[string]string{"env": "prod"}))
	idx := c.index.Load()
	assert.Equal(t, sets.New("prod"), idx.byUser["prod-user"].namespaces)
	assert.Equal(t, sets.New("prod"), idx.byGroup["prod-group"].namespaces)
	// The allowAll subjects are left alone: still nil, and no panic from inserting into a nil set.
	assert.Nil(t, idx.byUser["admin"].namespaces)
	assert.True(t, idx.byUser["admin"].allowAll)
	assert.Nil(t, idx.byUser["inconsistent"].namespaces)

	// A non-matching Namespace is not added.
	c.syncNamespace(newNamespace("dev", map[string]string{"env": "dev"}))
	idx = c.index.Load()
	assert.Equal(t, sets.New("prod"), idx.byUser["prod-user"].namespaces)

	// Re-applying the same Namespace is idempotent.
	c.syncNamespace(newNamespace("prod", map[string]string{"env": "prod"}))
	idx = c.index.Load()
	assert.Equal(t, sets.New("prod"), idx.byUser["prod-user"].namespaces)

	// A Namespace that stops matching is dropped.
	c.syncNamespace(newNamespace("prod", map[string]string{"env": "staging"}))
	idx = c.index.Load()
	assert.Equal(t, sets.New[string](), idx.byUser["prod-user"].namespaces)
	assert.Equal(t, sets.New[string](), idx.byGroup["prod-group"].namespaces)

	// A Namespace with no labels at all matches nothing, for a selector that requires a label.
	c.syncNamespace(newNamespace("bare", nil))
	idx = c.index.Load()
	assert.Equal(t, sets.New[string](), idx.byUser["prod-user"].namespaces)
}

// TestSyncNamespaceUnlabelled pins the case that a negated selector distinguishes: a Namespace with
// no labels at all is a perfectly ordinary Namespace, and must not be confused with a deleted one.
// A selector that matches every Namespace *without* a given label has to match it, and the
// incremental path must agree with the full rebuild in syncFlowAccessControls on that.
func TestSyncNamespaceUnlabelled(t *testing.T) {
	notOptedOut := trackedSubject(t, &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "exclude-from-flows", Operator: metav1.LabelSelectorOpDoesNotExist},
		},
	})
	c := newTestController(map[string]*subjectState{"everyone": notOptedOut}, map[string]*subjectState{})

	// nil labels, not an empty map: this is what the informer holds for a Namespace created
	// without any labels, and it is also the value the deletion path uses internally.
	bare := newNamespace("bare", nil)
	require.Nil(t, bare.Labels)
	c.syncNamespace(bare)
	assert.Equal(t, sets.New("bare"), c.index.Load().byUser["everyone"].namespaces,
		"an unlabelled Namespace must match a DoesNotExist selector")

	// The full rebuild must reach the same conclusion for the same Namespace.
	assert.True(t, notOptedOut.matches(bare.Labels), "syncFlowAccessControls would disagree with syncNamespace")

	// Deleting it is what removes it, and nothing else.
	c.removeNamespace("bare")
	assert.Equal(t, sets.New[string](), c.index.Load().byUser["everyone"].namespaces,
		"a deleted Namespace must not remain visible")
}

// TestRemoveNamespace exercises the Namespace deletion path directly, without informers.
func TestRemoveNamespace(t *testing.T) {
	prodUser := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	prodUser.namespaces = sets.New("prod", "prod2")
	adminUser := &subjectState{allowAll: true}
	prodGroup := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	prodGroup.namespaces = sets.New("prod")

	c := newTestController(
		map[string]*subjectState{"prod-user": prodUser, "admin": adminUser},
		map[string]*subjectState{"prod-group": prodGroup},
	)

	c.removeNamespace("prod")
	idx := c.index.Load()
	assert.Equal(t, sets.New("prod2"), idx.byUser["prod-user"].namespaces)
	assert.Equal(t, sets.New[string](), idx.byGroup["prod-group"].namespaces)
	assert.Nil(t, idx.byUser["admin"].namespaces)

	// Removing a Namespace that was never tracked is a no-op.
	c.removeNamespace("never-existed")
	idx = c.index.Load()
	assert.Equal(t, sets.New("prod2"), idx.byUser["prod-user"].namespaces)
}

// TestChecker exercises the read path directly, against a hand-built index.
func TestChecker(t *testing.T) {
	c := newTestController(
		map[string]*subjectState{
			"alice": {namespaces: sets.New("frontend")},
			"admin": {allowAll: true},
		},
		map[string]*subjectState{
			"backend-team": {namespaces: sets.New("backend")},
			"cluster-ops":  {allowAll: true},
		},
	)

	// A user's own grant and its groups' grants are OR-ed.
	both := c.VisibilityCheckerFor("alice", []string{"backend-team"})
	assert.False(t, both.AllowsAll())
	assert.True(t, both.AllowsNamespace("frontend"))
	assert.True(t, both.AllowsNamespace("backend"))
	assert.False(t, both.AllowsNamespace("other"))

	// An allowAll grant allows every Namespace, from either a User or a Group subject, and
	// whatever the user's other subjects grant.
	viaUser := c.VisibilityCheckerFor("admin", []string{"backend-team"})
	assert.True(t, viaUser.AllowsAll())
	assert.True(t, viaUser.AllowsNamespace("anything"))
	viaGroup := c.VisibilityCheckerFor("alice", []string{"cluster-ops"})
	assert.True(t, viaGroup.AllowsAll())
	assert.True(t, viaGroup.AllowsNamespace("anything"))

	// A scoped grant is not allowAll, even though it allows something.
	assert.False(t, c.VisibilityCheckerFor("alice", nil).AllowsAll())

	// An unknown subject is allowed nothing.
	nobody := c.VisibilityCheckerFor("nobody", []string{"nobody-group"})
	assert.False(t, nobody.AllowsAll())
	assert.False(t, nobody.AllowsNamespace("frontend"))

	// An empty index allows nothing either, which is what a Checker created before the informers
	// have synced sees.
	empty := newTestController(map[string]*subjectState{}, map[string]*subjectState{}).VisibilityCheckerFor("alice", []string{"backend-team"})
	assert.False(t, empty.AllowsAll())
	assert.False(t, empty.AllowsNamespace("frontend"))
}

type testFixture struct {
	*Controller
	crdClient     *crdfake.Clientset
	crdInformers  crdinformers.SharedInformerFactory
	k8sClient     *k8sfake.Clientset
	coreInformers informers.SharedInformerFactory
}

func newTestFixture(t *testing.T, namespaces []*v1.Namespace, facs []*crdv1alpha1.FlowAccessControl) *testFixture {
	t.Helper()

	nsObjs := make([]runtime.Object, len(namespaces))
	for i, ns := range namespaces {
		nsObjs[i] = ns
	}
	facObjs := make([]runtime.Object, len(facs))
	for i, fac := range facs {
		facObjs[i] = fac
	}

	k8sClient := k8sfake.NewSimpleClientset(nsObjs...)
	crdClient := crdfake.NewSimpleClientset(facObjs...)

	coreInformerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)

	controller := NewController(crdInformerFactory.Crd().V1alpha1().FlowAccessControls(), coreInformerFactory.Core().V1().Namespaces())

	return &testFixture{
		Controller:    controller,
		crdClient:     crdClient,
		crdInformers:  crdInformerFactory,
		k8sClient:     k8sClient,
		coreInformers: coreInformerFactory,
	}
}

func (f *testFixture) start(t *testing.T, stopCh chan struct{}) {
	t.Helper()
	f.coreInformers.Start(stopCh)
	f.coreInformers.WaitForCacheSync(stopCh)
	f.crdInformers.Start(stopCh)
	f.crdInformers.WaitForCacheSync(stopCh)
	go f.Controller.Run(stopCh)
}

// assertVisibleNamespaces waits until the given VisibilityChecker agrees exactly with want: every Namespace
// in want is visible to it, and every other Namespace the controller knows about is not.
//
// It probes the Namespaces the informer still knows about, so a Namespace that no longer exists can
// never show up in the result no matter what the index holds. Names in doesNotWant are probed
// explicitly on top of those, which is the only way to assert that a deleted Namespace was really
// dropped from the index rather than merely gone from the lister.
//
// The tests deliberately build a VisibilityChecker once and then keep asserting on it across successive
// changes, since that is how a flow stream uses one: obtained at stream start, consulted per
// record for as long as the stream lives.
func (f *testFixture) assertVisibleNamespaces(t *testing.T, checker VisibilityChecker, want, doesNotWant sets.Set[string], msg string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.False(c, checker.AllowsAll())
		namespaces, err := f.namespaceLister.List(labels.Everything())
		if !assert.NoError(c, err) {
			return
		}
		got := sets.New[string]()
		for _, ns := range namespaces {
			if checker.AllowsNamespace(ns.Name) {
				got.Insert(ns.Name)
			}
		}
		assert.Equal(c, want, got)
		for _, name := range sets.List(doesNotWant) {
			assert.False(c, checker.AllowsNamespace(name), "Namespace %s must not be visible", name)
		}
	}, 2*time.Second, 10*time.Millisecond, msg)
}

// assertAllowsAll waits until the given VisibilityChecker reports cluster-wide visibility.
func (f *testFixture) assertAllowsAll(t *testing.T, checker VisibilityChecker, msg string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, checker.AllowsAll())
		assert.True(c, checker.AllowsNamespace("any-namespace-at-all"))
	}, 2*time.Second, 10*time.Millisecond, msg)
}

// TestControllerHasSynced pins the contract the consumer relies on to tell "not ready yet" apart
// from "this subject has no grant": HasSynced must not report true until the index actually
// reflects the FlowAccessControl objects in the cluster.
func TestControllerHasSynced(t *testing.T) {
	prodNS := newNamespace("prod", map[string]string{"env": "prod"})
	fac := newFlowAccessControl(
		"frank-access",
		[]crdv1alpha1.FlowAccessSubject{userSubject("frank")},
		selectorForLabels(map[string]string{"env": "prod"}),
	)

	f := newTestFixture(t, []*v1.Namespace{prodNS}, []*crdv1alpha1.FlowAccessControl{fac})
	assert.False(t, f.HasSynced(), "HasSynced must be false before Run")

	stopCh := make(chan struct{})
	defer close(stopCh)
	f.start(t, stopCh)

	// Once HasSynced is true, the grant must already be visible, with no further waiting.
	require.Eventually(t, f.HasSynced, 2*time.Second, 10*time.Millisecond, "HasSynced never became true")
	assert.True(t, f.VisibilityCheckerFor("frank", nil).AllowsNamespace("prod"),
		"HasSynced reported true before the index reflected the FlowAccessControl")
}

func TestControllerIndex(t *testing.T) {
	frontendNS := newNamespace("frontend", map[string]string{"team": "frontend", v1.LabelMetadataName: "frontend"})
	backendNS := newNamespace("backend", map[string]string{"team": "backend", v1.LabelMetadataName: "backend"})

	facSelector := newFlowAccessControl(
		"frontend-team",
		[]crdv1alpha1.FlowAccessSubject{groupSubject("frontend-team")},
		selectorForLabels(map[string]string{"team": "frontend"}),
	)
	// Explicit Namespace names are expressed via the well-known name label.
	facByName := newFlowAccessControl(
		"alice-access",
		[]crdv1alpha1.FlowAccessSubject{userSubject("alice")},
		selectorForName("backend"),
	)
	// A ServiceAccount subject resolves for the identity the authenticator produces for it.
	facServiceAccount := newFlowAccessControl(
		"monitoring-sa-access",
		[]crdv1alpha1.FlowAccessSubject{serviceAccountSubject("monitoring", "collector")},
		selectorForLabels(map[string]string{"team": "frontend"}),
	)
	// A ServiceAccount subject with no Namespace is malformed. Admission rejects it, but the CEL
	// rule that does so is inert on Kubernetes 1.23/1.24, so the controller must skip it rather
	// than index "system:serviceaccount::orphan".
	facOrphanServiceAccount := newFlowAccessControl(
		"orphan-sa-access",
		[]crdv1alpha1.FlowAccessSubject{{Kind: crdv1alpha1.FlowAccessSubjectKindServiceAccount, Name: "orphan"}},
		selectorForLabels(map[string]string{"team": "frontend"}),
	)
	// A null namespaceSelector grants nothing, unlike an empty one. Admission rejects this too,
	// so it only exists for objects predating that validation.
	facNullSelector := newFlowAccessControl(
		"eve-access",
		[]crdv1alpha1.FlowAccessSubject{userSubject("eve")},
		nil,
	)
	facAdmin := newFlowAccessControl(
		"admin-access",
		[]crdv1alpha1.FlowAccessSubject{userSubject("admin")},
		&metav1.LabelSelector{},
	)

	f := newTestFixture(t,
		[]*v1.Namespace{frontendNS, backendNS},
		[]*crdv1alpha1.FlowAccessControl{facSelector, facByName, facServiceAccount, facOrphanServiceAccount, facNullSelector, facAdmin},
	)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.start(t, stopCh)

	f.assertVisibleNamespaces(t, f.VisibilityCheckerFor("random-user", []string{"frontend-team"}), sets.New("frontend"), nil,
		"group subject via namespaceSelector did not resolve")
	f.assertVisibleNamespaces(t, f.VisibilityCheckerFor("alice", nil), sets.New("backend"), nil,
		"user subject via name label selector did not resolve")
	// A user's own grant and its groups' grants are OR-ed together.
	f.assertVisibleNamespaces(t, f.VisibilityCheckerFor("alice", []string{"frontend-team"}), sets.New("frontend", "backend"), nil,
		"user and group grants were not OR-ed")

	f.assertVisibleNamespaces(t, f.VisibilityCheckerFor(serviceaccount.MakeUsername("monitoring", "collector"), nil), sets.New("frontend"), nil,
		"ServiceAccount subject did not resolve for its system:serviceaccount username")

	f.assertAllowsAll(t, f.VisibilityCheckerFor("admin", nil), "an empty namespaceSelector did not grant allowAll")
	// An allowAll grant via any one subject wins, whatever the other subjects grant.
	f.assertAllowsAll(t, f.VisibilityCheckerFor("admin", []string{"frontend-team"}),
		"allowAll user grant was not honored alongside a scoped group grant")

	// The index has settled by now, so the fail-closed cases can be asserted without polling.

	// A user with no matching FlowAccessControl subject gets no visibility.
	nobody := f.VisibilityCheckerFor("nobody", []string{"nobody-group"})
	assert.False(t, nobody.AllowsAll())
	assert.False(t, nobody.AllowsNamespace("frontend"))
	assert.False(t, nobody.AllowsNamespace("backend"))

	// A null namespaceSelector grants nothing rather than everything.
	eve := f.VisibilityCheckerFor("eve", nil)
	assert.False(t, eve.AllowsAll())
	assert.False(t, eve.AllowsNamespace("frontend"))
	assert.False(t, eve.AllowsNamespace("backend"))

	// A ServiceAccount subject without a Namespace is skipped, and in particular does not index
	// under a username with an empty Namespace.
	orphan := f.VisibilityCheckerFor(serviceaccount.MakeUsername("", "orphan"), nil)
	assert.False(t, orphan.AllowsAll())
	assert.False(t, orphan.AllowsNamespace("frontend"))
}

// TestControllerNamespaceEvents pins the property that motivates watching Namespaces at all: a
// VisibilityChecker obtained once — as a flow stream does at stream start — must reflect every later
// Namespace change, so that relabelling a Namespace out of a user's grant stops that user's
// established stream from receiving any further flows for it.
func TestControllerNamespaceEvents(t *testing.T) {
	staging := newNamespace("staging", map[string]string{"env": "staging"})
	fac := newFlowAccessControl(
		"env-staging",
		[]crdv1alpha1.FlowAccessSubject{groupSubject("staging-team")},
		selectorForLabels(map[string]string{"env": "staging"}),
	)

	f := newTestFixture(t, []*v1.Namespace{staging}, []*crdv1alpha1.FlowAccessControl{fac})
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.start(t, stopCh)

	// Obtained up front, and never rebuilt for the rest of the test.
	checker := f.VisibilityCheckerFor("u", []string{"staging-team"})
	f.assertVisibleNamespaces(t, checker, sets.New("staging"), nil, "initial index did not include staging Namespace")

	// Relabel the Namespace so it no longer matches: the incremental path must drop it.
	updated := staging.DeepCopy()
	updated.Labels = map[string]string{"env": "production"}
	_, err := f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New[string](), nil, "index was not updated after Namespace label change")

	// Relabel it back: the incremental path must re-add it.
	updated = updated.DeepCopy()
	updated.Labels = map[string]string{"env": "staging"}
	_, err = f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New("staging"), nil, "index was not updated after Namespace was relabelled back")

	// A newly created matching Namespace must be picked up.
	_, err = f.k8sClient.CoreV1().Namespaces().Create(context.Background(), newNamespace("staging2", map[string]string{"env": "staging"}), metav1.CreateOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New("staging", "staging2"), nil, "newly added Namespace was not picked up")

	// Deleting a Namespace must remove it from the index.
	err = f.k8sClient.CoreV1().Namespaces().Delete(context.Background(), "staging", metav1.DeleteOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New("staging2"), sets.New("staging"), "deleted Namespace was not removed from the index")
}

// TestControllerOverlappingGrants covers the case that makes naive incremental removal wrong: two
// FlowAccessControl objects granting the same Namespace to the same subject. When one stops
// matching, the Namespace must remain visible via the other.
func TestControllerOverlappingGrants(t *testing.T) {
	shared := newNamespace("shared", map[string]string{"team": "platform", "tier": "prod"})

	facByTeam := newFlowAccessControl(
		"by-team",
		[]crdv1alpha1.FlowAccessSubject{userSubject("carol")},
		selectorForLabels(map[string]string{"team": "platform"}),
	)
	facByTier := newFlowAccessControl(
		"by-tier",
		[]crdv1alpha1.FlowAccessSubject{userSubject("carol")},
		selectorForLabels(map[string]string{"tier": "prod"}),
	)

	f := newTestFixture(t, []*v1.Namespace{shared}, []*crdv1alpha1.FlowAccessControl{facByTeam, facByTier})
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.start(t, stopCh)

	checker := f.VisibilityCheckerFor("carol", nil)
	f.assertVisibleNamespaces(t, checker, sets.New("shared"), nil, "Namespace granted by two objects was not visible")

	// Drop the "team" label: the "tier" selector still matches, so the Namespace must stay visible.
	updated := shared.DeepCopy()
	updated.Labels = map[string]string{"tier": "prod"}
	_, err := f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New("shared"), nil,
		"Namespace was incorrectly removed while still matched by another FlowAccessControl")

	// Drop the remaining label: now nothing matches, so it must disappear.
	updated = updated.DeepCopy()
	updated.Labels = map[string]string{}
	_, err = f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New[string](), nil,
		"Namespace was not removed after it stopped matching every FlowAccessControl")
}

func TestControllerFlowAccessControlEvents(t *testing.T) {
	prodNS := newNamespace("prod", map[string]string{"env": "prod"})
	devNS := newNamespace("dev", map[string]string{"env": "dev"})

	fac := newFlowAccessControl(
		"dave-access",
		[]crdv1alpha1.FlowAccessSubject{userSubject("dave")},
		selectorForLabels(map[string]string{"env": "prod"}),
	)

	f := newTestFixture(t, []*v1.Namespace{prodNS, devNS}, []*crdv1alpha1.FlowAccessControl{fac})
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.start(t, stopCh)

	// As in TestControllerNamespaceEvents, the Checker is obtained once and must track every later
	// change, including the admin revoking the grant outright.
	checker := f.VisibilityCheckerFor("dave", nil)
	f.assertVisibleNamespaces(t, checker, sets.New("prod"), nil, "initial index did not resolve")

	// Changing the selector must re-evaluate against all Namespaces.
	updated := fac.DeepCopy()
	updated.Spec.NamespaceSelector = selectorForLabels(map[string]string{"env": "dev"})
	_, err := f.crdClient.CrdV1alpha1().FlowAccessControls().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New("dev"), nil, "index was not rebuilt after FlowAccessControl update")

	// Emptying the selector grants cluster-wide visibility.
	updated = updated.DeepCopy()
	updated.Spec.NamespaceSelector = &metav1.LabelSelector{}
	_, err = f.crdClient.CrdV1alpha1().FlowAccessControls().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertAllowsAll(t, checker, "emptying the namespaceSelector did not grant allowAll")

	// Nulling it out again grants nothing, which is the deliberate asymmetry with the empty
	// selector just above.
	updated = updated.DeepCopy()
	updated.Spec.NamespaceSelector = nil
	_, err = f.crdClient.CrdV1alpha1().FlowAccessControls().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New[string](), nil, "nulling the namespaceSelector did not revoke access")

	// Deleting the object revokes access entirely.
	err = f.crdClient.CrdV1alpha1().FlowAccessControls().Delete(context.Background(), updated.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
	f.assertVisibleNamespaces(t, checker, sets.New[string](), nil, "deleting the FlowAccessControl did not revoke access")
}

// Sized to roughly match the scenario from
// https://github.com/antrea-io/antrea/pull/8221#pullrequestreview-4837245493: 50 subjects (25
// users, 25 groups), 500 Namespaces, 6 groups checked per identity.
const (
	benchUserCount       = 25
	benchGroupCount      = 25
	benchNamespaceCount  = 500
	benchShardCount      = 25 // number of distinct Namespace shards subjects select on
	benchGroupsPerLookup = 6
)

func benchNamespaces() []*v1.Namespace {
	namespaces := make([]*v1.Namespace, benchNamespaceCount)
	for i := range namespaces {
		namespaces[i] = newNamespace(fmt.Sprintf("ns-%d", i), map[string]string{"shard": fmt.Sprintf("%d", i%benchShardCount)})
	}
	return namespaces
}

// benchSubjectStates builds 25 user subjects and 25 group subjects, each selecting on one shard
// label and pre-populated against the given Namespaces.
func benchSubjectStates(namespaces []*v1.Namespace) (byUser, byGroup map[string]*subjectState) {
	build := func(count int, prefix string) map[string]*subjectState {
		out := make(map[string]*subjectState, count)
		for i := 0; i < count; i++ {
			fac := newFlowAccessControl("bench", []crdv1alpha1.FlowAccessSubject{userSubject("x")}, selectorForLabels(map[string]string{"shard": fmt.Sprintf("%d", i%benchShardCount)}))
			selector, _ := parseNamespaceSelector(fac)
			state := &subjectState{selectors: []labels.Selector{selector}, namespaces: sets.New[string]()}
			for _, ns := range namespaces {
				if state.matches(ns.Labels) {
					state.namespaces.Insert(ns.Name)
				}
			}
			out[fmt.Sprintf("%s-%d", prefix, i)] = state
		}
		return out
	}
	return build(benchUserCount, "user"), build(benchGroupCount, "group")
}

// benchGroupsFor returns benchGroupsPerLookup distinct group keys for the i-th simulated identity.
func benchGroupsFor(i int) []string {
	groups := make([]string, benchGroupsPerLookup)
	for j := range groups {
		groups[j] = fmt.Sprintf("group-%d", (i+j)%benchGroupCount)
	}
	return groups
}

// BenchmarkReadWithWriter measures the per-flow-record read path (AllowsNamespace) under N
// concurrent readers and the one concurrent writer the controller always has in practice
// (syncNamespace runs on the single controller worker). It exists to check that the
// atomic.Pointer[subjectIndex] + copy-on-write design does not let that writer stall readers, which
// a sync.RWMutex + in-place-mutation design measurably does. Run with -cpu=1,2,4,8 to sweep
// GOMAXPROCS.
//
// Measured on an Apple M4 Pro (14 cores) with -benchtime=2s, against a variant of this package
// using sync.RWMutex + in-place mutation instead (ns/op, lower is better):
//
//	GOMAXPROCS   RWMutex   atomic COW   RWMutex+writer   atomic COW+writer
//	1              20.2        21.1            984.4                40.4
//	2              49.8        10.2            716.5                15.4
//	4              72.1         5.0            540.0                 6.7
//	8              92.0         2.7            304.4                 3.5
//
// Two things to note. Go's RWMutex reader path is an atomic read-modify-write on one shared cache
// line, so adding cores makes the RWMutex read path slower (20 -> 92 ns) while the atomic one scales
// (21 -> 2.7 ns). And because the write lock is held across every subject, one concurrent writer
// costs the RWMutex 7.5x at 4 cores versus 1.3x here.
func BenchmarkReadWithWriter(b *testing.B) {
	namespaces := benchNamespaces()
	byUser, byGroup := benchSubjectStates(namespaces)
	c := &Controller{}
	c.index.Store(&subjectIndex{byUser: byUser, byGroup: byGroup})

	var stop atomic.Bool
	defer stop.Store(true)
	go func() {
		flip := false
		for !stop.Load() {
			shard := "0"
			if flip {
				shard = "999" // never matches any subject's selector
			}
			flip = !flip
			c.syncNamespace(newNamespace(namespaces[0].Name, map[string]string{"shard": shard}))
		}
	}()

	// Everything the measured loop needs is built up front. Formatting a username and allocating a
	// group slice per iteration costs several hundred ns, which would bury the handful of map
	// lookups under test and make any two index designs look identical. A VisibilityChecker is
	// obtained once per stream in practice, not per record, so it is precomputed for the same
	// reason.
	checkers := make([]VisibilityChecker, benchUserCount)
	for i := range checkers {
		checkers[i] = c.VisibilityCheckerFor(fmt.Sprintf("user-%d", i), benchGroupsFor(i))
	}
	nsNames := make([]string, len(namespaces))
	for i, ns := range namespaces {
		nsNames[i] = ns.Name
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			checkers[i%len(checkers)].AllowsNamespace(nsNames[i%len(nsNames)])
			i++
		}
	})
}
