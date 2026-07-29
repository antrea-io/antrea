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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
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

func newFlowAccessControl(name string, subjects []crdv1alpha1.FlowAccessSubject, selectors ...metav1.LabelSelector) *crdv1alpha1.FlowAccessControl {
	return &crdv1alpha1.FlowAccessControl{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: crdv1alpha1.FlowAccessControlSpec{
			Subjects:           subjects,
			NamespaceSelectors: selectors,
		},
	}
}

func userSubject(name string) crdv1alpha1.FlowAccessSubject {
	return crdv1alpha1.FlowAccessSubject{Kind: crdv1alpha1.FlowAccessSubjectKindUser, Name: name}
}

func groupSubject(name string) crdv1alpha1.FlowAccessSubject {
	return crdv1alpha1.FlowAccessSubject{Kind: crdv1alpha1.FlowAccessSubjectKindGroup, Name: name}
}

func selectorForLabels(l map[string]string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: l}
}

// selectorForName builds a selector matching a single Namespace by name, which is how explicit
// Namespace names are expressed now that the API only takes label selectors.
func selectorForName(name string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: map[string]string{v1.LabelMetadataName: name}}
}

func TestParseNamespaceSelectors(t *testing.T) {
	tests := []struct {
		name          string
		selectors     []metav1.LabelSelector
		wantAllowAll  bool
		wantSelectors int
	}{
		{
			name:         "no selectors means allowAll",
			selectors:    nil,
			wantAllowAll: true,
		},
		{
			name:         "empty selector list means allowAll",
			selectors:    []metav1.LabelSelector{},
			wantAllowAll: true,
		},
		{
			name:         "wildcard selector means allowAll",
			selectors:    []metav1.LabelSelector{{}},
			wantAllowAll: true,
		},
		{
			name:         "wildcard among several selectors means allowAll",
			selectors:    []metav1.LabelSelector{selectorForLabels(map[string]string{"team": "frontend"}), {}},
			wantAllowAll: true,
		},
		{
			name:          "single selector",
			selectors:     []metav1.LabelSelector{selectorForLabels(map[string]string{"team": "frontend"})},
			wantSelectors: 1,
		},
		{
			name: "several selectors are kept",
			selectors: []metav1.LabelSelector{
				selectorForLabels(map[string]string{"team": "frontend"}),
				selectorForName("backend"),
			},
			wantSelectors: 2,
		},
		{
			name: "invalid selector is dropped, valid one kept",
			selectors: []metav1.LabelSelector{
				selectorForLabels(map[string]string{"team": "frontend"}),
				{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "team", Operator: "BogusOperator"}}},
			},
			wantSelectors: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fac := newFlowAccessControl("test", []crdv1alpha1.FlowAccessSubject{userSubject("alice")}, tt.selectors...)
			gotSelectors, gotAllowAll := parseNamespaceSelectors(fac)
			assert.Equal(t, tt.wantAllowAll, gotAllowAll)
			if !tt.wantAllowAll {
				assert.Len(t, gotSelectors, tt.wantSelectors)
			}
		})
	}
}

func TestSubjectStateMatches(t *testing.T) {
	fac := newFlowAccessControl(
		"test",
		[]crdv1alpha1.FlowAccessSubject{userSubject("alice")},
		selectorForLabels(map[string]string{"team": "frontend"}),
		selectorForName("backend"),
	)
	selectors, allowAll := parseNamespaceSelectors(fac)
	require.False(t, allowAll)
	state := &subjectState{selectors: selectors}

	// Matches via the first selector.
	assert.True(t, state.matches(labels.Set{"team": "frontend"}))
	// Matches via the second (name-based) selector.
	assert.True(t, state.matches(labels.Set{v1.LabelMetadataName: "backend"}))
	// Matches neither.
	assert.False(t, state.matches(labels.Set{"team": "other"}))
	assert.False(t, state.matches(labels.Set{}))
}

// trackedSubject builds the cached state of a subject with the given selectors, i.e. one that is
// not cluster-wide and therefore has its Namespace set maintained.
func trackedSubject(t *testing.T, selectors ...metav1.LabelSelector) *subjectState {
	t.Helper()
	fac := newFlowAccessControl("test", []crdv1alpha1.FlowAccessSubject{userSubject("x")}, selectors...)
	parsed, allowAll := parseNamespaceSelectors(fac)
	require.False(t, allowAll)
	return &subjectState{selectors: parsed, namespaces: sets.New[string]()}
}

// TestApplyNamespace exercises the incremental Namespace path directly, without informers.
func TestApplyNamespace(t *testing.T) {
	prodUser := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	// An allowAll subject has a nil namespaces set and must be skipped entirely.
	adminUser := &subjectState{allowAll: true}
	// A deliberately inconsistent subject: allowAll (so a nil namespaces set) but carrying a
	// selector that matches. syncFlowAccessControls never produces this, but if the allowAll guard
	// in forEachTrackedSubject were dropped, this subject would take the Insert branch and panic
	// with "assignment to entry in nil map". This pins that guard.
	inconsistentUser := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	inconsistentUser.allowAll = true
	inconsistentUser.namespaces = nil
	prodGroup := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))

	c := &Controller{
		byUser: map[string]*subjectState{
			"prod-user":    prodUser,
			"admin":        adminUser,
			"inconsistent": inconsistentUser,
		},
		byGroup: map[string]*subjectState{"prod-group": prodGroup},
	}

	// A matching Namespace is added, for both User and Group subjects.
	c.onNamespaceAdd(newNamespace("prod", map[string]string{"env": "prod"}))
	assert.Equal(t, sets.New("prod"), prodUser.namespaces)
	assert.Equal(t, sets.New("prod"), prodGroup.namespaces)
	// The allowAll subjects are left alone: still nil, and no panic from inserting into a nil set.
	assert.Nil(t, adminUser.namespaces)
	assert.True(t, adminUser.allowAll)
	assert.Nil(t, inconsistentUser.namespaces)

	// A non-matching Namespace is not added.
	c.onNamespaceAdd(newNamespace("dev", map[string]string{"env": "dev"}))
	assert.Equal(t, sets.New("prod"), prodUser.namespaces)

	// Re-applying the same Namespace is idempotent.
	c.onNamespaceAdd(newNamespace("prod", map[string]string{"env": "prod"}))
	assert.Equal(t, sets.New("prod"), prodUser.namespaces)

	// A Namespace that stops matching is dropped.
	c.onNamespaceAdd(newNamespace("prod", map[string]string{"env": "staging"}))
	assert.Equal(t, sets.New[string](), prodUser.namespaces)
	assert.Equal(t, sets.New[string](), prodGroup.namespaces)

	// A Namespace with no labels at all matches nothing.
	c.onNamespaceAdd(newNamespace("bare", nil))
	assert.Equal(t, sets.New[string](), prodUser.namespaces)
}

// TestRemoveNamespace exercises the Namespace deletion path directly, without informers.
func TestRemoveNamespace(t *testing.T) {
	prodUser := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	prodUser.namespaces = sets.New("prod", "prod2")
	adminUser := &subjectState{allowAll: true}
	prodGroup := trackedSubject(t, selectorForLabels(map[string]string{"env": "prod"}))
	prodGroup.namespaces = sets.New("prod")

	c := &Controller{
		byUser:  map[string]*subjectState{"prod-user": prodUser, "admin": adminUser},
		byGroup: map[string]*subjectState{"prod-group": prodGroup},
	}

	c.onNamespaceDelete("prod")
	assert.Equal(t, sets.New("prod2"), prodUser.namespaces)
	assert.Equal(t, sets.New[string](), prodGroup.namespaces)
	assert.Nil(t, adminUser.namespaces)

	// Removing a Namespace that was never tracked is a no-op.
	c.onNamespaceDelete("never-existed")
	assert.Equal(t, sets.New("prod2"), prodUser.namespaces)
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

// assertAllowedNamespaces waits until the given subject resolves to the expected Namespace set.
func (f *testFixture) assertAllowedNamespaces(t *testing.T, username string, groups []string, want sets.Set[string], msg string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, allowAll := f.AllowedNamespaces(username, groups)
		assert.False(c, allowAll)
		assert.Equal(c, want, got)
	}, 2*time.Second, 10*time.Millisecond, msg)
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
	// Several selectors on one object are OR-ed together.
	facMultiSelector := newFlowAccessControl(
		"bob-access",
		[]crdv1alpha1.FlowAccessSubject{userSubject("bob")},
		selectorForLabels(map[string]string{"team": "frontend"}),
		selectorForName("backend"),
	)
	facAdmin := newFlowAccessControl(
		"admin-access",
		[]crdv1alpha1.FlowAccessSubject{userSubject("admin")},
	)

	f := newTestFixture(t,
		[]*v1.Namespace{frontendNS, backendNS},
		[]*crdv1alpha1.FlowAccessControl{facSelector, facByName, facMultiSelector, facAdmin},
	)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.start(t, stopCh)

	f.assertAllowedNamespaces(t, "random-user", []string{"frontend-team"}, sets.New("frontend"),
		"group subject via namespaceSelector did not resolve")
	f.assertAllowedNamespaces(t, "alice", nil, sets.New("backend"),
		"user subject via name label selector did not resolve")
	f.assertAllowedNamespaces(t, "bob", nil, sets.New("frontend", "backend"),
		"multiple selectors on one object were not OR-ed")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, allowAll := f.AllowedNamespaces("admin", nil)
		assert.True(c, allowAll)
	}, 2*time.Second, 10*time.Millisecond, "omitting namespaceSelectors did not grant allowAll")

	// A user with no matching FlowAccessControl subject gets no visibility (fail-closed).
	got, allowAll := f.AllowedNamespaces("nobody", []string{"nobody-group"})
	assert.False(t, allowAll)
	assert.Empty(t, got)
}

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

	group := []string{"staging-team"}
	f.assertAllowedNamespaces(t, "u", group, sets.New("staging"), "initial index did not include staging Namespace")

	// Relabel the Namespace so it no longer matches: the incremental path must drop it.
	updated := staging.DeepCopy()
	updated.Labels = map[string]string{"env": "production"}
	_, err := f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertAllowedNamespaces(t, "u", group, sets.New[string](), "index was not updated after Namespace label change")

	// Relabel it back: the incremental path must re-add it.
	updated = updated.DeepCopy()
	updated.Labels = map[string]string{"env": "staging"}
	_, err = f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertAllowedNamespaces(t, "u", group, sets.New("staging"), "index was not updated after Namespace was relabelled back")

	// A newly created matching Namespace must be picked up.
	_, err = f.k8sClient.CoreV1().Namespaces().Create(context.Background(), newNamespace("staging2", map[string]string{"env": "staging"}), metav1.CreateOptions{})
	require.NoError(t, err)
	f.assertAllowedNamespaces(t, "u", group, sets.New("staging", "staging2"), "newly added Namespace was not picked up")

	// Deleting a Namespace must remove it from the index.
	err = f.k8sClient.CoreV1().Namespaces().Delete(context.Background(), "staging", metav1.DeleteOptions{})
	require.NoError(t, err)
	f.assertAllowedNamespaces(t, "u", group, sets.New("staging2"), "deleted Namespace was not removed from the index")
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

	f.assertAllowedNamespaces(t, "carol", nil, sets.New("shared"), "Namespace granted by two objects was not visible")

	// Drop the "team" label: the "tier" selector still matches, so the Namespace must stay visible.
	updated := shared.DeepCopy()
	updated.Labels = map[string]string{"tier": "prod"}
	_, err := f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertAllowedNamespaces(t, "carol", nil, sets.New("shared"),
		"Namespace was incorrectly removed while still matched by another FlowAccessControl")

	// Drop the remaining label: now nothing matches, so it must disappear.
	updated = updated.DeepCopy()
	updated.Labels = map[string]string{}
	_, err = f.k8sClient.CoreV1().Namespaces().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertAllowedNamespaces(t, "carol", nil, sets.New[string](),
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

	f.assertAllowedNamespaces(t, "dave", nil, sets.New("prod"), "initial index did not resolve")

	// Widening the selector must re-evaluate against all Namespaces.
	updated := fac.DeepCopy()
	updated.Spec.NamespaceSelectors = []metav1.LabelSelector{selectorForLabels(map[string]string{"env": "dev"})}
	_, err := f.crdClient.CrdV1alpha1().FlowAccessControls().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.assertAllowedNamespaces(t, "dave", nil, sets.New("dev"), "index was not rebuilt after FlowAccessControl update")

	// Removing all selectors grants cluster-wide visibility.
	updated = updated.DeepCopy()
	updated.Spec.NamespaceSelectors = nil
	_, err = f.crdClient.CrdV1alpha1().FlowAccessControls().Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, allowAll := f.AllowedNamespaces("dave", nil)
		assert.True(c, allowAll)
	}, 2*time.Second, 10*time.Millisecond, "clearing namespaceSelectors did not grant allowAll")

	// Deleting the object revokes access entirely.
	err = f.crdClient.CrdV1alpha1().FlowAccessControls().Delete(context.Background(), updated.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, allowAll := f.AllowedNamespaces("dave", nil)
		assert.False(c, allowAll)
		assert.Empty(c, got)
	}, 2*time.Second, 10*time.Millisecond, "deleting the FlowAccessControl did not revoke access")
}
