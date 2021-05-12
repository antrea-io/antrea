// Copyright 2021 Antrea Authors
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

package crdmirroring

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	crdv1a1lister "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	crdv1a2lister "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/crdmirroring/crdhandler"
	"antrea.io/antrea/pkg/controller/crdmirroring/types"
	legacycore "antrea.io/antrea/pkg/legacyapis/core/v1alpha2"
	legacyops "antrea.io/antrea/pkg/legacyapis/ops/v1alpha1"
	legacysecurity "antrea.io/antrea/pkg/legacyapis/security/v1alpha1"
	legacycrdclientset "antrea.io/antrea/pkg/legacyclient/clientset/versioned"
	legacyfakeversioned "antrea.io/antrea/pkg/legacyclient/clientset/versioned/fake"
	legacycrdinformers "antrea.io/antrea/pkg/legacyclient/informers/externalversions"
	legacycorelister "antrea.io/antrea/pkg/legacyclient/listers/core/v1alpha2"
	legacyopslister "antrea.io/antrea/pkg/legacyclient/listers/ops/v1alpha1"
	legacysecuritylister "antrea.io/antrea/pkg/legacyclient/listers/security/v1alpha1"
)

const (
	informerDefaultResync = 30 * time.Second
	timeout               = 2 * time.Second
	mockWait              = 200 * time.Millisecond

	networkPolicy        = "NetworkPolicy"
	clusterNetworkPolicy = "ClusterNetworkPolicy"
	tier                 = "Tier"
	clusterGroup         = "ClusterGroup"
	externalEntity       = "ExternalEntity"
	traceflow            = "Traceflow"
)

var (
	labelSelector1 = metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	labelSelector2 = metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}

	endPoints1 = []crdv1alpha2.Endpoint{{IP: "192.168.1.1", Name: "ep1"}, {IP: "192.168.1.2", Name: "ep2"}}
	endPoints2 = []crdv1alpha2.Endpoint{{IP: "172.16.1.1", Name: "ep1"}, {IP: "172.16.1.2", Name: "ep2"}}

	priority1 float64 = 100
	priority2 float64 = 200

	spec1 = crdv1alpha1.TierSpec{Priority: 100, Description: "test1"}
	spec2 = crdv1alpha1.TierSpec{Priority: 200, Description: "test2"}

	source1 = crdv1alpha1.Source{Namespace: "test-namespace", Pod: "test-pod1"}
	source2 = crdv1alpha1.Source{Namespace: "test-namespace", Pod: "test-pod2"}

	conditions = []crdv1alpha2.GroupCondition{
		{
			Type:               crdv1alpha2.GroupConditionType("test"),
			Status:             v1.ConditionStatus("test"),
			LastTransitionTime: metav1.Time{Time: time.Now()},
		},
	}

	npStatus = crdv1alpha1.NetworkPolicyStatus{
		Phase: "test", ObservedGeneration: 1,
		CurrentNodesRealized: 1,
		DesiredNodesRealized: 3,
	}
	tfStatus = crdv1alpha1.TraceflowStatus{Phase: "test", Reason: "test", DataplaneTag: 1}
)

type mirroringController struct {
	*Controller
	client                *fakeversioned.Clientset
	legacyClient          *legacyfakeversioned.Clientset
	informerFactory       crdinformers.SharedInformerFactory
	legacyInformerFactory legacycrdinformers.SharedInformerFactory
	testHandler           mirroringTestHandler
	wg                    *sync.WaitGroup
}

func newMirroringController(crdName string) *mirroringController {
	client := fakeversioned.NewSimpleClientset()
	legacyClient := legacyfakeversioned.NewSimpleClientset()
	crdInformerFactory := crdinformers.NewSharedInformerFactory(client, informerDefaultResync)
	legacyCRDInformerFactory := legacycrdinformers.NewSharedInformerFactory(legacyClient, informerDefaultResync)

	var mirroringHandler types.MirroringHandler
	var informer, legacyInformer cache.SharedInformer
	var wg sync.WaitGroup
	m := &mirroringController{}

	switch crdName {
	case networkPolicy:
		crdInformer := crdInformerFactory.Crd().V1alpha1().NetworkPolicies()
		legacyCRDInformer := legacyCRDInformerFactory.Security().V1alpha1().NetworkPolicies()
		informer = crdInformer.Informer()
		legacyInformer = legacyCRDInformer.Informer()

		m.testHandler = NewNetworkPolicyTestHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)
		mirroringHandler = crdhandler.NewNetworkPolicyHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)

	case clusterNetworkPolicy:
		crdInformer := crdInformerFactory.Crd().V1alpha1().ClusterNetworkPolicies()
		legacyCRDInformer := legacyCRDInformerFactory.Security().V1alpha1().ClusterNetworkPolicies()
		informer = crdInformer.Informer()
		legacyInformer = legacyCRDInformer.Informer()

		m.testHandler = NewClusterNetworkPolicyTestHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)
		mirroringHandler = crdhandler.NewClusterNetworkPolicyHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client.CrdV1alpha1().ClusterNetworkPolicies(),
			legacyClient.SecurityV1alpha1().ClusterNetworkPolicies())

	case tier:
		crdInformer := crdInformerFactory.Crd().V1alpha1().Tiers()
		legacyCRDInformer := legacyCRDInformerFactory.Security().V1alpha1().Tiers()
		informer = crdInformer.Informer()
		legacyInformer = legacyCRDInformer.Informer()

		m.testHandler = NewTierTestHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)
		mirroringHandler = crdhandler.NewTierHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client.CrdV1alpha1().Tiers(),
			legacyClient.SecurityV1alpha1().Tiers())

	case clusterGroup:
		crdInformer := crdInformerFactory.Crd().V1alpha2().ClusterGroups()
		legacyCRDInformer := legacyCRDInformerFactory.Core().V1alpha2().ClusterGroups()
		informer = crdInformer.Informer()
		legacyInformer = legacyCRDInformer.Informer()

		m.testHandler = NewClusterGroupTestHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)
		mirroringHandler = crdhandler.NewClusterGroupHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client.CrdV1alpha2().ClusterGroups(),
			legacyClient.CoreV1alpha2().ClusterGroups())

	case externalEntity:
		crdInformer := crdInformerFactory.Crd().V1alpha2().ExternalEntities()
		legacyCRDInformer := legacyCRDInformerFactory.Core().V1alpha2().ExternalEntities()
		informer = crdInformer.Informer()
		legacyInformer = legacyCRDInformer.Informer()

		m.testHandler = NewExternalEntityTestHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)
		mirroringHandler = crdhandler.NewExternalEntityHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)

	case traceflow:
		crdInformer := crdInformerFactory.Crd().V1alpha1().Traceflows()
		legacyCRDInformer := legacyCRDInformerFactory.Ops().V1alpha1().Traceflows()
		informer = crdInformer.Informer()
		legacyInformer = legacyCRDInformer.Informer()

		m.testHandler = NewTraceflowTestHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client,
			legacyClient)
		mirroringHandler = crdhandler.NewTraceflowHandler(crdInformer.Lister(),
			legacyCRDInformer.Lister(),
			client.CrdV1alpha1().Traceflows(),
			legacyClient.OpsV1alpha1().Traceflows())
	}

	c := NewController(informer, legacyInformer, mirroringHandler, crdName)

	m.Controller = c
	m.client = client
	m.legacyClient = legacyClient
	m.informerFactory = crdInformerFactory
	m.legacyInformerFactory = legacyCRDInformerFactory
	m.wg = &wg

	return m
}

func buildObj(crdName, namespace, name string) metav1.Object {
	var obj metav1.Object

	switch crdName {
	case networkPolicy:
		obj = &legacysecurity.NetworkPolicy{}
		obj.SetNamespace(namespace)
		obj.(*legacysecurity.NetworkPolicy).Spec.Priority = priority1
	case clusterNetworkPolicy:
		obj = &legacysecurity.ClusterNetworkPolicy{}
		obj.(*legacysecurity.ClusterNetworkPolicy).Spec.Priority = priority1
	case tier:
		obj = &legacysecurity.Tier{}
		obj.(*legacysecurity.Tier).Spec = spec1
	case clusterGroup:
		obj = &legacycore.ClusterGroup{}
		obj.(*legacycore.ClusterGroup).Spec.PodSelector = &labelSelector1
	case externalEntity:
		obj = &legacycore.ExternalEntity{}
		obj.SetNamespace(namespace)
		obj.(*legacycore.ExternalEntity).Spec.Endpoints = endPoints1
	case traceflow:
		obj = &legacyops.Traceflow{}
		obj.(*legacyops.Traceflow).Spec.Source = source1
	}
	obj.SetName(name)
	obj.SetLabels(map[string]string{}) // init labels

	return obj
}

func updateLegacyObj(crdName string, obj metav1.Object) metav1.Object {
	res := deepCopy(obj)
	switch crdName {
	case networkPolicy:
		res.(*legacysecurity.NetworkPolicy).Spec.Priority = priority2
	case clusterNetworkPolicy:
		res.(*legacysecurity.ClusterNetworkPolicy).Spec.Priority = priority2
	case tier:
		res.(*legacysecurity.Tier).Spec = spec2
	case clusterGroup:
		res.(*legacycore.ClusterGroup).Spec.PodSelector = &labelSelector2
	case externalEntity:
		res.(*legacycore.ExternalEntity).Spec.Endpoints = endPoints2
	case traceflow:
		res.(*legacyops.Traceflow).Spec.Source = source2
	}
	return res
}

func updateLegacyObjAnnotation(obj metav1.Object) metav1.Object {
	res := deepCopy(obj)
	res.SetAnnotations(map[string]string{types.StopMirror: "true"})
	return res
}

func updateNewObj(crdName string, obj metav1.Object) metav1.Object {
	res := deepCopy(obj)
	switch crdName {
	case networkPolicy:
		res.(*crdv1alpha1.NetworkPolicy).Spec.Priority = priority2
	case clusterNetworkPolicy:
		res.(*crdv1alpha1.ClusterNetworkPolicy).Spec.Priority = priority2
	case tier:
		res.(*crdv1alpha1.Tier).DeepCopy().Spec = spec2
	case clusterGroup:
		res.(*crdv1alpha2.ClusterGroup).Spec.PodSelector = &labelSelector2
	case externalEntity:
		res.(*crdv1alpha2.ExternalEntity).Spec.Endpoints = endPoints2
	case traceflow:
		res.(*crdv1alpha1.Traceflow).Spec.Source = source2
	}
	return res
}

func updateNewObjStatus(crdName string, obj metav1.Object) metav1.Object {
	res := deepCopy(obj)
	switch crdName {
	case networkPolicy:
		res.(*crdv1alpha1.NetworkPolicy).Status = npStatus
	case clusterNetworkPolicy:
		res.(*crdv1alpha1.ClusterNetworkPolicy).Status = npStatus
	case clusterGroup:
		res.(*crdv1alpha2.ClusterGroup).Status.Conditions = conditions
	case traceflow:
		res.(*crdv1alpha1.Traceflow).Status = tfStatus
	}
	return res
}

func assertSpec(t *testing.T, crdName string, expectedObj, res metav1.Object) {
	switch crdName {
	case networkPolicy:
		assert.Equal(t, expectedObj.(*legacysecurity.NetworkPolicy).Spec, res.(*crdv1alpha1.NetworkPolicy).Spec)
	case clusterNetworkPolicy:
		assert.Equal(t, expectedObj.(*legacysecurity.ClusterNetworkPolicy).Spec, res.(*crdv1alpha1.ClusterNetworkPolicy).Spec)
	case tier:
		assert.Equal(t, expectedObj.(*legacysecurity.Tier).Spec, res.(*crdv1alpha1.Tier).Spec)
	case clusterGroup:
		assert.Equal(t, expectedObj.(*legacycore.ClusterGroup).Spec, res.(*crdv1alpha2.ClusterGroup).Spec)
	case externalEntity:
		assert.Equal(t, expectedObj.(*legacycore.ExternalEntity).Spec, res.(*crdv1alpha2.ExternalEntity).Spec)
	case traceflow:
		assert.Equal(t, expectedObj.(*legacyops.Traceflow).Spec, res.(*crdv1alpha1.Traceflow).Spec)
	}
}

type mirroringTestHandler interface {
	LegacyAddAndWait(obj metav1.Object) (metav1.Object, error)
	LegacyDeleteAndWait(namespace, name string) error
	LegacyUpdateAndWait(obj metav1.Object) (metav1.Object, error)
	NewLiberateAndWait(obj metav1.Object) (metav1.Object, metav1.Object, error)
	NewDeleteAndWait(namespace, name string) error
	NewUpdateAndWait(legacyObj, newObj metav1.Object) (metav1.Object, error)
	NewUpdateStatusAndWait(res metav1.Object) error
}

// ClusterGroup
type ClusterGroupTestHandler struct {
	lister       crdv1a2lister.ClusterGroupLister
	client       crdclientset.Interface
	legacyLister legacycorelister.ClusterGroupLister
	legacyClient legacycrdclientset.Interface
}

func NewClusterGroupTestHandler(lister crdv1a2lister.ClusterGroupLister,
	legacyLister legacycorelister.ClusterGroupLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) *ClusterGroupTestHandler {
	nt := &ClusterGroupTestHandler{
		client:       client,
		lister:       lister,
		legacyClient: legacyClient,
		legacyLister: legacyLister,
	}
	return nt
}

func (c *ClusterGroupTestHandler) LegacyAddAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacycore.ClusterGroup)
	_, err := c.legacyClient.CoreV1alpha2().ClusterGroups().Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewReady(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *ClusterGroupTestHandler) LegacyDeleteAndWait(namespace, name string) error {
	err := c.legacyClient.CoreV1alpha2().ClusterGroups().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	err = c.waitForNewDeleted(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterGroupTestHandler) LegacyUpdateAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacycore.ClusterGroup)
	_, err := c.legacyClient.CoreV1alpha2().ClusterGroups().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewUpdated(crd.Namespace, crd.Name, crd.Spec, crd.Labels, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *ClusterGroupTestHandler) NewLiberateAndWait(obj metav1.Object) (metav1.Object, metav1.Object, error) {
	crd := obj.(*legacycore.ClusterGroup)
	res1, err := c.legacyClient.CoreV1alpha2().ClusterGroups().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, nil, err
	}

	res2, err := c.waitForNewLiberate(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, nil, err
	}
	return res1, res2, nil
}

func (c *ClusterGroupTestHandler) NewDeleteAndWait(namespace, name string) error {
	err := c.client.CrdV1alpha2().ClusterGroups().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	time.Sleep(mockWait)
	_, err = c.waitForNewReady(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterGroupTestHandler) NewUpdateAndWait(legacyObj, newObj metav1.Object) (metav1.Object, error) {
	crd := newObj.(*crdv1alpha2.ClusterGroup)
	lCRD := legacyObj.(*legacycore.ClusterGroup)
	_, err := c.client.CrdV1alpha2().ClusterGroups().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	time.Sleep(mockWait)
	res, err := c.waitForNewUpdated(lCRD.Namespace, lCRD.Name, lCRD.Spec, lCRD.Labels, timeout)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *ClusterGroupTestHandler) NewUpdateStatusAndWait(obj metav1.Object) error {
	crd := obj.(*crdv1alpha2.ClusterGroup)
	_, err := c.client.CrdV1alpha2().ClusterGroups().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	time.Sleep(mockWait)
	err = c.waitForLegacyUpdated(crd.Namespace, crd.Name, crd.Status, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterGroupTestHandler) waitForNewReady(namespace, name string, timeout time.Duration) (*crdv1alpha2.ClusterGroup, error) {
	var crd *crdv1alpha2.ClusterGroup
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *ClusterGroupTestHandler) waitForNewDeleted(namespace, name string, timeout time.Duration) error {
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		_, err = c.lister.Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *ClusterGroupTestHandler) waitForNewUpdated(namespace, name string, spec crdv1alpha2.GroupSpec, labels map[string]string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha2.ClusterGroup
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil && reflect.DeepEqual(crd.Spec, spec) && reflect.DeepEqual(crd.Labels, labels) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *ClusterGroupTestHandler) waitForLegacyUpdated(namespace, name string, status crdv1alpha2.GroupStatus, timeout time.Duration) error {
	var crd *legacycore.ClusterGroup
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.legacyLister.Get(name)
		if err == nil && reflect.DeepEqual(crd.Status, status) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *ClusterGroupTestHandler) waitForNewLiberate(namespace, name string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha2.ClusterGroup
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil {
			if _, exist := crd.Annotations[types.ManagedBy]; !exist {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

// ExternalEntityTestHandler
type ExternalEntityTestHandler struct {
	lister       crdv1a2lister.ExternalEntityLister
	client       crdclientset.Interface
	legacyLister legacycorelister.ExternalEntityLister
	legacyClient legacycrdclientset.Interface
}

func NewExternalEntityTestHandler(lister crdv1a2lister.ExternalEntityLister,
	legacyLister legacycorelister.ExternalEntityLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) *ExternalEntityTestHandler {
	nt := &ExternalEntityTestHandler{
		client:       client,
		lister:       lister,
		legacyClient: legacyClient,
		legacyLister: legacyLister,
	}
	return nt
}

func (c *ExternalEntityTestHandler) LegacyAddAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacycore.ExternalEntity)
	_, err := c.legacyClient.CoreV1alpha2().ExternalEntities(crd.Namespace).Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewReady(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *ExternalEntityTestHandler) LegacyDeleteAndWait(namespace, name string) error {
	err := c.legacyClient.CoreV1alpha2().ExternalEntities(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	err = c.waitForNewDeleted(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ExternalEntityTestHandler) LegacyUpdateAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacycore.ExternalEntity)
	_, err := c.legacyClient.CoreV1alpha2().ExternalEntities(crd.Namespace).Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewUpdated(crd.Namespace, crd.Name, crd.Spec, crd.Labels, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *ExternalEntityTestHandler) NewLiberateAndWait(obj metav1.Object) (metav1.Object, metav1.Object, error) {
	crd := obj.(*legacycore.ExternalEntity)
	res1, err := c.legacyClient.CoreV1alpha2().ExternalEntities(crd.Namespace).Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, nil, err
	}

	res2, err := c.waitForNewLiberate(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, nil, err
	}
	return res1, res2, nil
}

func (c *ExternalEntityTestHandler) NewDeleteAndWait(namespace, name string) error {
	err := c.client.CrdV1alpha2().ExternalEntities(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	time.Sleep(mockWait)
	_, err = c.waitForNewReady(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ExternalEntityTestHandler) NewUpdateAndWait(legacyObj, newObj metav1.Object) (metav1.Object, error) {
	crd := newObj.(*crdv1alpha2.ExternalEntity)
	lCRD := legacyObj.(*legacycore.ExternalEntity)
	_, err := c.client.CrdV1alpha2().ExternalEntities(crd.Namespace).Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	time.Sleep(mockWait)
	res, err := c.waitForNewUpdated(lCRD.Namespace, lCRD.Name, lCRD.Spec, lCRD.Labels, timeout)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *ExternalEntityTestHandler) NewUpdateStatusAndWait(obj metav1.Object) error {
	return nil
}

func (c *ExternalEntityTestHandler) waitForNewReady(namespace, name string, timeout time.Duration) (*crdv1alpha2.ExternalEntity, error) {
	var crd *crdv1alpha2.ExternalEntity
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.ExternalEntities(namespace).Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *ExternalEntityTestHandler) waitForNewDeleted(namespace, name string, timeout time.Duration) error {
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		_, err = c.lister.ExternalEntities(namespace).Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *ExternalEntityTestHandler) waitForNewUpdated(namespace, name string, spec crdv1alpha2.ExternalEntitySpec, labels map[string]string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha2.ExternalEntity
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.ExternalEntities(namespace).Get(name)
		if err == nil && reflect.DeepEqual(crd.Spec, spec) && reflect.DeepEqual(crd.Labels, labels) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *ExternalEntityTestHandler) waitForNewLiberate(namespace, name string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha2.ExternalEntity
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.ExternalEntities(namespace).Get(name)
		if err == nil {
			if _, exist := crd.Annotations[types.ManagedBy]; !exist {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

// NetworkPolicyTestHandler
type NetworkPolicyTestHandler struct {
	lister       crdv1a1lister.NetworkPolicyLister
	client       crdclientset.Interface
	legacyLister legacysecuritylister.NetworkPolicyLister
	legacyClient legacycrdclientset.Interface
}

func NewNetworkPolicyTestHandler(lister crdv1a1lister.NetworkPolicyLister,
	legacyLister legacysecuritylister.NetworkPolicyLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) *NetworkPolicyTestHandler {
	nt := &NetworkPolicyTestHandler{
		client:       client,
		lister:       lister,
		legacyClient: legacyClient,
		legacyLister: legacyLister,
	}
	return nt
}

func (c *NetworkPolicyTestHandler) LegacyAddAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacysecurity.NetworkPolicy)
	_, err := c.legacyClient.SecurityV1alpha1().NetworkPolicies(crd.Namespace).Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewReady(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *NetworkPolicyTestHandler) LegacyDeleteAndWait(namespace, name string) error {
	err := c.legacyClient.SecurityV1alpha1().NetworkPolicies(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	err = c.waitForNewDeleted(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *NetworkPolicyTestHandler) LegacyUpdateAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacysecurity.NetworkPolicy)
	_, err := c.legacyClient.SecurityV1alpha1().NetworkPolicies(crd.Namespace).Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewUpdated(crd.Namespace, crd.Name, crd.Spec, crd.Labels, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *NetworkPolicyTestHandler) NewLiberateAndWait(obj metav1.Object) (metav1.Object, metav1.Object, error) {
	crd := obj.(*legacysecurity.NetworkPolicy)
	res1, err := c.legacyClient.SecurityV1alpha1().NetworkPolicies(crd.Namespace).Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, nil, err
	}

	res2, err := c.waitForNewLiberate(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, nil, err
	}
	return res1, res2, nil
}

func (c *NetworkPolicyTestHandler) NewDeleteAndWait(namespace, name string) error {
	err := c.client.CrdV1alpha1().NetworkPolicies(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	time.Sleep(mockWait)
	_, err = c.waitForNewReady(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *NetworkPolicyTestHandler) NewUpdateAndWait(legacyObj, newObj metav1.Object) (metav1.Object, error) {
	crd := newObj.(*crdv1alpha1.NetworkPolicy)
	lCRD := legacyObj.(*legacysecurity.NetworkPolicy)
	_, err := c.client.CrdV1alpha1().NetworkPolicies(crd.Namespace).Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	time.Sleep(mockWait)
	res, err := c.waitForNewUpdated(lCRD.Namespace, lCRD.Name, lCRD.Spec, lCRD.Labels, timeout)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *NetworkPolicyTestHandler) NewUpdateStatusAndWait(obj metav1.Object) error {
	crd := obj.(*crdv1alpha1.NetworkPolicy)
	_, err := c.client.CrdV1alpha1().NetworkPolicies(crd.Namespace).UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	time.Sleep(mockWait)
	err = c.waitForLegacyUpdated(crd.Namespace, crd.Name, crd.Status, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *NetworkPolicyTestHandler) waitForNewReady(namespace, name string, timeout time.Duration) (*crdv1alpha1.NetworkPolicy, error) {
	var crd *crdv1alpha1.NetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.NetworkPolicies(namespace).Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *NetworkPolicyTestHandler) waitForNewDeleted(namespace, name string, timeout time.Duration) error {
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		_, err = c.lister.NetworkPolicies(namespace).Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *NetworkPolicyTestHandler) waitForNewUpdated(namespace, name string, spec crdv1alpha1.NetworkPolicySpec, labels map[string]string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.NetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.NetworkPolicies(namespace).Get(name)
		if err == nil && reflect.DeepEqual(crd.Spec, spec) && reflect.DeepEqual(crd.Labels, labels) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *NetworkPolicyTestHandler) waitForLegacyUpdated(namespace, name string, status crdv1alpha1.NetworkPolicyStatus, timeout time.Duration) error {
	var crd *legacysecurity.NetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.legacyLister.NetworkPolicies(namespace).Get(name)
		if err == nil && reflect.DeepEqual(crd.Status, status) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *NetworkPolicyTestHandler) waitForNewLiberate(namespace, name string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.NetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.NetworkPolicies(namespace).Get(name)
		if err == nil {
			if _, exist := crd.Annotations[types.ManagedBy]; !exist {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

// ClusterNetworkPolicyTestHandler
type ClusterNetworkPolicyTestHandler struct {
	lister       crdv1a1lister.ClusterNetworkPolicyLister
	client       crdclientset.Interface
	legacyLister legacysecuritylister.ClusterNetworkPolicyLister
	legacyClient legacycrdclientset.Interface
}

func NewClusterNetworkPolicyTestHandler(lister crdv1a1lister.ClusterNetworkPolicyLister,
	legacyLister legacysecuritylister.ClusterNetworkPolicyLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) *ClusterNetworkPolicyTestHandler {
	nt := &ClusterNetworkPolicyTestHandler{
		client:       client,
		lister:       lister,
		legacyClient: legacyClient,
		legacyLister: legacyLister,
	}
	return nt
}

func (c *ClusterNetworkPolicyTestHandler) LegacyAddAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacysecurity.ClusterNetworkPolicy)
	_, err := c.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies().Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewReady(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *ClusterNetworkPolicyTestHandler) LegacyDeleteAndWait(namespace, name string) error {
	err := c.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	err = c.waitForNewDeleted(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterNetworkPolicyTestHandler) LegacyUpdateAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacysecurity.ClusterNetworkPolicy)
	_, err := c.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewUpdated(crd.Namespace, crd.Name, crd.Spec, crd.Labels, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *ClusterNetworkPolicyTestHandler) NewLiberateAndWait(obj metav1.Object) (metav1.Object, metav1.Object, error) {
	crd := obj.(*legacysecurity.ClusterNetworkPolicy)
	res1, err := c.legacyClient.SecurityV1alpha1().ClusterNetworkPolicies().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, nil, err
	}

	res2, err := c.waitForNewLiberate(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, nil, err
	}
	return res1, res2, nil
}

func (c *ClusterNetworkPolicyTestHandler) NewDeleteAndWait(namespace, name string) error {
	err := c.client.CrdV1alpha1().ClusterNetworkPolicies().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	time.Sleep(mockWait)
	_, err = c.waitForNewReady(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterNetworkPolicyTestHandler) NewUpdateAndWait(legacyObj, newObj metav1.Object) (metav1.Object, error) {
	crd := newObj.(*crdv1alpha1.ClusterNetworkPolicy)
	lCRD := legacyObj.(*legacysecurity.ClusterNetworkPolicy)
	_, err := c.client.CrdV1alpha1().ClusterNetworkPolicies().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	time.Sleep(mockWait)
	res, err := c.waitForNewUpdated(lCRD.Namespace, lCRD.Name, lCRD.Spec, lCRD.Labels, timeout)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *ClusterNetworkPolicyTestHandler) NewUpdateStatusAndWait(obj metav1.Object) error {
	crd := obj.(*crdv1alpha1.ClusterNetworkPolicy)
	_, err := c.client.CrdV1alpha1().ClusterNetworkPolicies().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	time.Sleep(mockWait)
	err = c.waitForLegacyUpdated(crd.Namespace, crd.Name, crd.Status, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterNetworkPolicyTestHandler) waitForNewReady(namespace, name string, timeout time.Duration) (*crdv1alpha1.ClusterNetworkPolicy, error) {
	var crd *crdv1alpha1.ClusterNetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *ClusterNetworkPolicyTestHandler) waitForNewDeleted(namespace, name string, timeout time.Duration) error {
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		_, err = c.lister.Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *ClusterNetworkPolicyTestHandler) waitForNewUpdated(namespace, name string, spec crdv1alpha1.ClusterNetworkPolicySpec, labels map[string]string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.ClusterNetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil && reflect.DeepEqual(crd.Spec, spec) && reflect.DeepEqual(crd.Labels, labels) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *ClusterNetworkPolicyTestHandler) waitForLegacyUpdated(namespace, name string, status crdv1alpha1.NetworkPolicyStatus, timeout time.Duration) error {
	var crd *legacysecurity.ClusterNetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.legacyLister.Get(name)
		if err == nil && reflect.DeepEqual(crd.Status, status) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *ClusterNetworkPolicyTestHandler) waitForNewLiberate(namespace, name string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.ClusterNetworkPolicy
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil {
			if _, exist := crd.Annotations[types.ManagedBy]; !exist {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

// TierTestHandler
type TierTestHandler struct {
	lister       crdv1a1lister.TierLister
	client       crdclientset.Interface
	legacyLister legacysecuritylister.TierLister
	legacyClient legacycrdclientset.Interface
}

func NewTierTestHandler(lister crdv1a1lister.TierLister,
	legacyLister legacysecuritylister.TierLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) *TierTestHandler {
	nt := &TierTestHandler{
		client:       client,
		lister:       lister,
		legacyClient: legacyClient,
		legacyLister: legacyLister,
	}
	return nt
}

func (c *TierTestHandler) LegacyAddAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacysecurity.Tier)
	_, err := c.legacyClient.SecurityV1alpha1().Tiers().Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewReady(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *TierTestHandler) LegacyDeleteAndWait(namespace, name string) error {
	err := c.legacyClient.SecurityV1alpha1().Tiers().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	err = c.waitForNewDeleted(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *TierTestHandler) LegacyUpdateAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacysecurity.Tier)
	_, err := c.legacyClient.SecurityV1alpha1().Tiers().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewUpdated(crd.Namespace, crd.Name, crd.Spec, crd.Labels, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *TierTestHandler) NewLiberateAndWait(obj metav1.Object) (metav1.Object, metav1.Object, error) {
	crd := obj.(*legacysecurity.Tier)
	res1, err := c.legacyClient.SecurityV1alpha1().Tiers().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, nil, err
	}

	res2, err := c.waitForNewLiberate(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, nil, err
	}
	return res1, res2, nil
}

func (c *TierTestHandler) NewDeleteAndWait(namespace, name string) error {
	err := c.client.CrdV1alpha1().Tiers().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	time.Sleep(mockWait)
	_, err = c.waitForNewReady(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *TierTestHandler) NewUpdateAndWait(legacyObj, newObj metav1.Object) (metav1.Object, error) {
	crd := newObj.(*crdv1alpha1.Tier)
	lCRD := legacyObj.(*legacysecurity.Tier)
	_, err := c.client.CrdV1alpha1().Tiers().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	time.Sleep(mockWait)
	res, err := c.waitForNewUpdated(lCRD.Namespace, lCRD.Name, lCRD.Spec, lCRD.Labels, timeout)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *TierTestHandler) NewUpdateStatusAndWait(obj metav1.Object) error {
	return nil
}

func (c *TierTestHandler) waitForNewReady(namespace, name string, timeout time.Duration) (*crdv1alpha1.Tier, error) {
	var crd *crdv1alpha1.Tier
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *TierTestHandler) waitForNewDeleted(namespace, name string, timeout time.Duration) error {
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		_, err = c.lister.Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *TierTestHandler) waitForNewUpdated(namespace, name string, spec crdv1alpha1.TierSpec, labels map[string]string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.Tier
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil && reflect.DeepEqual(crd.Spec, spec) && reflect.DeepEqual(crd.Labels, labels) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *TierTestHandler) waitForNewLiberate(namespace, name string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.Tier
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil {
			if _, exist := crd.Annotations[types.ManagedBy]; !exist {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

// TraceflowTestHandler
type TraceflowTestHandler struct {
	lister       crdv1a1lister.TraceflowLister
	client       crdclientset.Interface
	legacyLister legacyopslister.TraceflowLister
	legacyClient legacycrdclientset.Interface
}

func NewTraceflowTestHandler(lister crdv1a1lister.TraceflowLister,
	legacyLister legacyopslister.TraceflowLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) *TraceflowTestHandler {
	nt := &TraceflowTestHandler{
		client:       client,
		lister:       lister,
		legacyClient: legacyClient,
		legacyLister: legacyLister,
	}
	return nt
}

func (c *TraceflowTestHandler) LegacyAddAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacyops.Traceflow)
	_, err := c.legacyClient.OpsV1alpha1().Traceflows().Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewReady(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *TraceflowTestHandler) LegacyDeleteAndWait(namespace, name string) error {
	err := c.legacyClient.OpsV1alpha1().Traceflows().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	err = c.waitForNewDeleted(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *TraceflowTestHandler) LegacyUpdateAndWait(obj metav1.Object) (metav1.Object, error) {
	crd := obj.(*legacyops.Traceflow)
	_, err := c.legacyClient.OpsV1alpha1().Traceflows().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.waitForNewUpdated(crd.Namespace, crd.Name, crd.Spec, crd.Labels, timeout)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *TraceflowTestHandler) NewLiberateAndWait(obj metav1.Object) (metav1.Object, metav1.Object, error) {
	crd := obj.(*legacyops.Traceflow)
	res1, err := c.legacyClient.OpsV1alpha1().Traceflows().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, nil, err
	}

	res2, err := c.waitForNewLiberate(crd.Namespace, crd.Name, timeout)
	if err != nil {
		return nil, nil, err
	}
	return res1, res2, nil
}

func (c *TraceflowTestHandler) NewDeleteAndWait(namespace, name string) error {
	err := c.client.CrdV1alpha1().Traceflows().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	time.Sleep(mockWait)
	_, err = c.waitForNewReady(namespace, name, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *TraceflowTestHandler) NewUpdateAndWait(legacyObj, newObj metav1.Object) (metav1.Object, error) {
	crd := newObj.(*crdv1alpha1.Traceflow)
	lCRD := legacyObj.(*legacyops.Traceflow)
	_, err := c.client.CrdV1alpha1().Traceflows().Update(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	time.Sleep(mockWait)
	res, err := c.waitForNewUpdated(lCRD.Namespace, lCRD.Name, lCRD.Spec, lCRD.Labels, timeout)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *TraceflowTestHandler) NewUpdateStatusAndWait(obj metav1.Object) error {
	crd := obj.(*crdv1alpha1.Traceflow)
	_, err := c.client.CrdV1alpha1().Traceflows().UpdateStatus(context.TODO(), crd, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	time.Sleep(mockWait)
	err = c.waitForLegacyUpdated(crd.Namespace, crd.Name, crd.Status, timeout)
	if err != nil {
		return err
	}
	return nil
}

func (c *TraceflowTestHandler) waitForNewReady(namespace, name string, timeout time.Duration) (*crdv1alpha1.Traceflow, error) {
	var crd *crdv1alpha1.Traceflow
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *TraceflowTestHandler) waitForNewDeleted(namespace, name string, timeout time.Duration) error {
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		_, err = c.lister.Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *TraceflowTestHandler) waitForNewUpdated(namespace, name string, spec crdv1alpha1.TraceflowSpec, labels map[string]string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.Traceflow
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil && reflect.DeepEqual(crd.Spec, spec) && reflect.DeepEqual(crd.Labels, labels) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

func (c *TraceflowTestHandler) waitForLegacyUpdated(namespace, name string, status crdv1alpha1.TraceflowStatus, timeout time.Duration) error {
	var crd *legacyops.Traceflow
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.legacyLister.Get(name)
		if err == nil && reflect.DeepEqual(crd.Status, status) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *TraceflowTestHandler) waitForNewLiberate(namespace, name string, timeout time.Duration) (metav1.Object, error) {
	var crd *crdv1alpha1.Traceflow
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		crd, err = c.lister.Get(name)
		if err == nil {
			if _, exist := crd.Annotations[types.ManagedBy]; !exist {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	return crd, nil
}

// mirroringController
func (c *mirroringController) testLegacyAdd(t *testing.T) {
	name := "legacy-add"
	namespace := "test"
	defer c.wg.Done()

	expectedObj := buildObj(c.crdName, namespace, name)
	resObj, err := c.testHandler.LegacyAddAndWait(expectedObj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyAddAndWait, got %v", err)
	}

	assert.NotNil(t, resObj)
	assert.Equal(t, expectedObj.GetName(), resObj.GetName())
	assert.Equal(t, expectedObj.GetLabels(), resObj.GetLabels())
	assertSpec(t, c.crdName, expectedObj, resObj)
}

func (c *mirroringController) testLegacyDelete(t *testing.T) {
	name := "legacy-delete"
	namespace := "test"
	defer c.wg.Done()

	obj := buildObj(c.crdName, namespace, name)
	_, err := c.testHandler.LegacyAddAndWait(obj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyAddAndWait, got %v", err)
	}

	err = c.testHandler.LegacyDeleteAndWait(namespace, name)
	if err != nil {
		t.Fatalf("Expected no error running LegacyDeleteAndWait, got %v", err)
	}
}

func (c *mirroringController) testLegacyUpdate(t *testing.T) {
	name := "legacy-update"
	namespace := "test"
	defer c.wg.Done()

	obj := buildObj(c.crdName, namespace, name)
	_, err := c.testHandler.LegacyAddAndWait(obj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyAddAndWait, got %v", err)
	}

	expectedObj := updateLegacyObj(c.crdName, obj)
	resObj, err := c.testHandler.LegacyUpdateAndWait(expectedObj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyUpdateAndWait, got %v", err)
	}
	assertSpec(t, c.crdName, expectedObj, resObj)
}

func (c *mirroringController) testNewLiberate(t *testing.T) {
	name := "new-liberate"
	namespace := "test"
	defer c.wg.Done()

	obj := buildObj(c.crdName, namespace, name)
	_, err := c.testHandler.LegacyAddAndWait(obj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyAddAndWait, got %v", err)
	}

	legacyObj, newObj, err := c.testHandler.NewLiberateAndWait(updateLegacyObjAnnotation(obj))
	if err != nil {
		t.Fatalf("Expected no error running NewLiberateAndWait, got %v", err)
	}

	_, managedBy := newObj.GetAnnotations()[types.ManagedBy]
	_, stopMirror := legacyObj.GetAnnotations()[types.StopMirror]

	assert.Equal(t, false, managedBy)
	assert.Equal(t, true, stopMirror)
}

func (c *mirroringController) testNewDelete(t *testing.T) {
	name := "new-delete"
	namespace := "test"
	defer c.wg.Done()

	obj := buildObj(c.crdName, namespace, name)
	_, err := c.testHandler.LegacyAddAndWait(obj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyAddAndWait, got %v", err)
	}

	err = c.testHandler.NewDeleteAndWait(namespace, name)
	if err != nil {
		t.Fatalf("Expected no error running NewDeleteAndWait, got %v", err)
	}
}

func (c *mirroringController) testNewUpdate(t *testing.T) {
	name := "new-update"
	namespace := "test"
	defer c.wg.Done()

	legacyObj := buildObj(c.crdName, namespace, name)
	newObj, err := c.testHandler.LegacyAddAndWait(legacyObj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyAddAndWait, got %v", err)
	}

	res, err := c.testHandler.NewUpdateAndWait(legacyObj, updateNewObj(c.crdName, newObj))
	if err != nil {
		t.Fatalf("Expected no error running NewUpdateAndWait, got %v", err)
	}
	assertSpec(t, c.crdName, legacyObj, res)
}

func (c *mirroringController) testNewUpdateStatus(t *testing.T) {
	name := "new-update-status"
	namespace := "test"
	defer c.wg.Done()

	obj := buildObj(c.crdName, namespace, name)
	res, err := c.testHandler.LegacyAddAndWait(obj)
	if err != nil {
		t.Fatalf("Expected no error running LegacyAddAndWait, got %v", err)
	}

	err = c.testHandler.NewUpdateStatusAndWait(updateNewObjStatus(c.crdName, res))
	if err != nil {
		t.Fatalf("Expected no error running NewUpdateStatusAndWait, got %v", err)
	}
}

func testCRD(t *testing.T, crd string) {
	controller := newMirroringController(crd)
	stopCh := make(chan struct{})
	controller.informerFactory.Start(stopCh)
	controller.legacyInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.legacyInformerFactory.WaitForCacheSync(stopCh)
	go controller.Run(stopCh)
	controller.wg.Add(7)

	t.Run("LegacyAdd", func(t *testing.T) { controller.testLegacyAdd(t) })
	t.Run("LegacyDelete", func(t *testing.T) { controller.testLegacyDelete(t) })
	t.Run("LegacyUpdate", func(t *testing.T) { controller.testLegacyUpdate(t) })
	t.Run("NewLiberate", func(t *testing.T) { controller.testNewLiberate(t) })
	t.Run("NewDelete", func(t *testing.T) { controller.testNewDelete(t) })
	t.Run("NewUpdate", func(t *testing.T) { controller.testNewUpdate(t) })
	t.Run("NewUpdateStatus", func(t *testing.T) { controller.testNewUpdateStatus(t) })

	controller.wg.Wait()
	close(stopCh)
}

func TestCRDMirroringController(t *testing.T) {
	t.Run(clusterGroup, func(t *testing.T) { testCRD(t, clusterGroup) })
	t.Run(externalEntity, func(t *testing.T) { testCRD(t, externalEntity) })
	t.Run(networkPolicy, func(t *testing.T) { testCRD(t, networkPolicy) })
	t.Run(clusterNetworkPolicy, func(t *testing.T) { testCRD(t, clusterNetworkPolicy) })
	t.Run(tier, func(t *testing.T) { testCRD(t, tier) })
	t.Run(traceflow, func(t *testing.T) { testCRD(t, traceflow) })
}
