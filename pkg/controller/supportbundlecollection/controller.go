// Copyright 2022 Antrea Authors
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

package supportbundlecollection

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apiserver/storage"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "SupportBundleCollectionController"
	// How long to wait before retrying the processing of an ExternalNode change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// supportBundleCollectionRetryPeriod is the duration after which to retry a SupportBundleCollection
	// request if it conflicts with a processing request.
	supportBundleCollectionRetryPeriod = time.Second * 10

	secretKeyWithAPIKey      = "apikey"
	secretKeyWithBearerToken = "token"
	secretKeyWithUsername    = "username"
	secretKeyWithPassword    = "password"
)

const (
	processingNodesIndex         = "processingNodes"
	processingExternalNodesIndex = "processingExternalNodes"
	processingNodesIndexValue    = "processingNodes"
)

// supportBundleCollectionAppliedTo is defined to maintain a SupportBundleCollection's required Nodes and ExternalNodes.
type supportBundleCollectionAppliedTo struct {
	// The name of a SupportBundleCollection
	name         string
	processNodes bool
	enNamespace  string
}

func getSupportBundleCollectionKey(obj interface{}) (string, error) {
	appliedTo := obj.(*supportBundleCollectionAppliedTo)
	return appliedTo.name, nil
}

func processingNodesIndexFunc(obj interface{}) ([]string, error) {
	appliedTo := obj.(*supportBundleCollectionAppliedTo)
	if !appliedTo.processNodes {
		return []string{}, nil
	}
	return []string{processingNodesIndexValue}, nil
}

func processingExternalNodesIndexFunc(obj interface{}) ([]string, error) {
	appliedTo := obj.(*supportBundleCollectionAppliedTo)
	if appliedTo.enNamespace == "" {
		return []string{}, nil
	}
	return []string{appliedTo.enNamespace}, nil
}

type Controller struct {
	kubeClient kubernetes.Interface
	crdClient  clientset.Interface

	supportBundleCollectionInformer     crdinformers.SupportBundleCollectionInformer
	supportBundleCollectionLister       crdlisters.SupportBundleCollectionLister
	supportBundleCollectionListerSynced cache.InformerSynced
	nodeLister                          corelisters.NodeLister
	nodeListerSynced                    cache.InformerSynced
	externalNodeLister                  crdlisters.ExternalNodeLister
	externalNodeListerSynced            cache.InformerSynced

	// queue maintains the ExternalNode objects that need to be synced.
	queue workqueue.RateLimitingInterface

	// supportBundleCollectionStore is the storage where the populated internal support bundle collections are stored.
	supportBundleCollectionStore storage.Interface
	// supportBundleCollectionAppliedToStore is the storage where the required Nodes or ExternalNodes of a
	// SupportBundleCollection are stored.
	supportBundleCollectionAppliedToStore cache.Indexer

	// statuses is a nested map that keeps the realization statuses reported by antrea-agents.
	// The outer map's keys are the SupportBundleCollection names. The inner map's keys are the Node names. The inner
	// map's values are statuses reported by each Node for a SupportBundleCollection.
	statuses     map[string]map[string]*controlplane.SupportBundleCollectionNodeStatus
	statusesLock sync.RWMutex
}

func NewSupportBundleCollectionController(
	kubeClient kubernetes.Interface,
	crdClient clientset.Interface,
	supportBundleInformer crdinformers.SupportBundleCollectionInformer,
	nodeInformer coreinformers.NodeInformer,
	externalNodeInformer crdinformers.ExternalNodeInformer,
	supportBundleCollectionStore storage.Interface) *Controller {
	c := &Controller{
		kubeClient: kubeClient,
		crdClient:  crdClient,

		supportBundleCollectionInformer:     supportBundleInformer,
		supportBundleCollectionLister:       supportBundleInformer.Lister(),
		supportBundleCollectionListerSynced: supportBundleInformer.Informer().HasSynced,
		nodeLister:                          nodeInformer.Lister(),
		nodeListerSynced:                    nodeInformer.Informer().HasSynced,
		externalNodeLister:                  externalNodeInformer.Lister(),
		externalNodeListerSynced:            externalNodeInformer.Informer().HasSynced,
		queue:                               workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "supportBundleCollection"),
		supportBundleCollectionStore:        supportBundleCollectionStore,
		supportBundleCollectionAppliedToStore: cache.NewIndexer(getSupportBundleCollectionKey, cache.Indexers{
			processingNodesIndex:         processingNodesIndexFunc,
			processingExternalNodesIndex: processingExternalNodesIndexFunc,
		}),
		statuses: make(map[string]map[string]*controlplane.SupportBundleCollectionNodeStatus),
	}
	c.supportBundleCollectionInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addSupportBundleCollection,
			UpdateFunc: c.updateSupportBundleCollection,
			DeleteFunc: c.deleteSupportBundleCollection,
		},
		resyncPeriod)
	return c
}

// Run will create defaultWorkers workers (goroutines) which will process the SupportBundle events from the work queue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.supportBundleCollectionListerSynced, c.nodeListerSynced, c.externalNodeListerSynced) {
		return
	}
	if err := c.reconcileSupportBundleCollections(); err != nil {
		klog.ErrorS(err, "Failed to reconcile SupportBundleCollection")
		return
	}

	go wait.Until(c.worker, time.Second, stopCh)

	<-stopCh
}

// UpdateStatus is called when Agent reports status to the internal SupportBundleCollection resource.
func (c *Controller) UpdateStatus(status *controlplane.SupportBundleCollectionStatus) error {
	key := status.Name
	_, found, _ := c.supportBundleCollectionStore.Get(key)
	if !found {
		klog.InfoS("SupportBundleCollection has been deleted, skip updating its status", "supportBundleCollection", key)
		return nil
	}
	func() {
		c.statusesLock.Lock()
		defer c.statusesLock.Unlock()
		statusPerNode, exists := c.statuses[key]
		if !exists {
			statusPerNode = map[string]*controlplane.SupportBundleCollectionNodeStatus{}
			c.statuses[key] = statusPerNode
		}
		for i := range status.Nodes {
			nodeStatus := status.Nodes[i]
			nodeStatusKey := getNodeKey(&nodeStatus)
			statusPerNode[nodeStatusKey] = &nodeStatus
		}
	}()
	c.queue.Add(key)
	return nil
}

func (c *Controller) addSupportBundleCollection(obj interface{}) {
	bundleCollection := obj.(*v1alpha1.SupportBundleCollection)
	if isCollectionCompleted(bundleCollection) {
		klog.InfoS("Processed SupportBundleCollection ADD event, collection is completed")
		return
	}
	c.queue.Add(bundleCollection.Name)
	klog.InfoS("Enqueued SupportBundleCollection ADD event", "name", bundleCollection.Name)
}

// updateSupportBundleCollection adds the SupportBundleCollection name into queue if the conditions are updated. The
// changes in SupportBundleCollection.Spec is ignored, as we do not support Spec changes after the collection is started.
func (c *Controller) updateSupportBundleCollection(oldObj, newObj interface{}) {
	bundleCollection := newObj.(*v1alpha1.SupportBundleCollection)
	oldBundleCollection := oldObj.(*v1alpha1.SupportBundleCollection)
	conditionChanged := !reflect.DeepEqual(bundleCollection.Status.Conditions, oldBundleCollection.Status.Conditions)
	if !conditionChanged {
		klog.V(2).InfoS("Processed SupportBundleCollection UPDATE event, Conditions not changed", "name", bundleCollection.Name)
		return
	}
	c.queue.Add(bundleCollection.Name)
	klog.InfoS("Enqueued SupportBundleCollection UPDATE event", "name", bundleCollection.Name)
}

func (c *Controller) deleteSupportBundleCollection(obj interface{}) {
	bundleCollection, ok := obj.(*v1alpha1.SupportBundleCollection)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Error decoding object when deleting SupportBundleCollection with invalid type", "object", obj)
			return
		}
		bundleCollection, ok = tombstone.Obj.(*v1alpha1.SupportBundleCollection)
		if !ok {
			klog.ErrorS(nil, "Error decoding object tombstone when deleting SupportBundleCollection with invalid type", "object", tombstone.Obj)
			return
		}
	}
	c.queue.Add(bundleCollection.Name)
	klog.InfoS("Enqueued SupportBundleCollection DELETE event", "name", bundleCollection.Name)
}

// reconcileExternalNodes reconciles all the existing support bundles which are in BundleProcessing phase.
func (c *Controller) reconcileSupportBundleCollections() error {
	bundleList, err := c.supportBundleCollectionLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, bundle := range bundleList {
		if isCollectionProcessing(bundle) {
			// Continue processing the started SupportBundleCollection request if it is not completed before restart.
			if _, err := c.createInternalSupportBundleCollection(bundle); err != nil {
				klog.ErrorS(err, "Failed to reconcile SupportBundleCollection", "name", bundle.Name)
			}
		}
	}

	return nil
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the work queue.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string in SupportBundleCollection work queue but got %#v", obj)
		return true
	} else if err := c.syncSupportBundleCollection(key); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing SupportBundleCollection", "name", key)
	}
	return true
}

func (c *Controller) syncSupportBundleCollection(key string) error {
	bundle, err := c.supportBundleCollectionLister.Get(key)
	if k8serrors.IsNotFound(err) {
		return c.deleteInternalSupportBundleCollection(key)
	}
	// If the SupportBundleCollection is completed, remove the internal SupportBundleCollection.
	if isCollectionCompleted(bundle) {
		return c.deleteInternalSupportBundleCollection(key)
	}
	if !c.isCollectionAvailable(bundle) {
		if err := c.processConflictedCollection(bundle); err != nil {
			return err
		}
		return nil
	}
	internalBundleCollectionObj, found, _ := c.supportBundleCollectionStore.Get(key)
	if !found {
		internalBundleCollectionObj, err = c.createInternalSupportBundleCollection(bundle)
		if err != nil {
			return err
		}
	}
	if internalBundleCollectionObj != nil {
		return c.updateStatus(internalBundleCollectionObj.(*types.SupportBundleCollection))
	}
	return nil
}

// createInternalSupportBundleCollection creates internal SupportBundle object and saves it into the storage.
func (c *Controller) createInternalSupportBundleCollection(bundle *v1alpha1.SupportBundleCollection) (*types.SupportBundleCollection, error) {
	// Calculate the expiration time with ExpirationMinutes and the created time of the resource.
	// It is to ensure the expiration time of the internal support bundle collection resource is constant, and to
	// ensure the processing is atomic even if SupportBundleCollectionController is restarted.
	expiredDuration, err := time.ParseDuration(fmt.Sprintf("%dm", bundle.Spec.ExpirationMinutes))
	if err != nil {
		klog.ErrorS(err, "Failed to parse expiration minute", "expirationMinute", bundle.Spec.ExpirationMinutes)
		return nil, err
	}
	expiredAt := bundle.ObjectMeta.CreationTimestamp.Add(expiredDuration)
	now := time.Now()
	transitionTime := metav1.Now()

	// Create a CollectionStarted failure condition on the CRD if time is expired. Return nil to avoid the event
	// to be re-enqueued.
	if !now.Before(expiredAt) {
		conditions := []v1alpha1.SupportBundleCollectionCondition{
			{
				Type:               v1alpha1.CollectionStarted,
				Status:             metav1.ConditionFalse,
				Reason:             string(metav1.StatusReasonExpired),
				LastTransitionTime: transitionTime,
			},
			{
				Type:               v1alpha1.BundleCollected,
				Status:             metav1.ConditionFalse,
				LastTransitionTime: transitionTime,
			},
			{
				Type:               v1alpha1.CollectionFailure,
				Status:             metav1.ConditionTrue,
				Reason:             string(metav1.StatusReasonExpired),
				LastTransitionTime: transitionTime,
			},
			{
				Type:               v1alpha1.CollectionCompleted,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: transitionTime,
			},
		}
		if err := c.addConditions(bundle.Name, conditions); err != nil {
			klog.ErrorS(err, "Failed to create a CollectionFailure condition")
			return nil, err
		}
		klog.InfoS("SupportBundleCollection is expired", "expiredAt", expiredAt, "now", now)
		return nil, nil
	}
	// Get expected Kubernetes Nodes defined in the CRD.
	nodeNames, err := c.getBundleNodes(bundle.Spec.Nodes)
	if err != nil {
		klog.ErrorS(err, "Failed to get Nodes defined in the support bundle", "name", bundle.Name)
		return nil, err
	}
	// Get expected external Nodes defined in the CRD.
	externalNodeNames, err := c.getBundleExternalNodes(bundle.Spec.ExternalNodes)
	if err != nil {
		klog.ErrorS(err, "Failed to get ExternalNodes defined in the support bundle", "name", bundle.Name)
		return nil, err
	}
	nodeSpan := nodeNames.Union(externalNodeNames)
	// Get authentication from the Secret provided in authentication field in the CRD
	authentication, err := c.parseBundleAuth(bundle.Spec.Authentication)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication defined in the SupportBundleCollection CR", "name", bundle.Name, "authentication", bundle.Spec.Authentication)
		return nil, err
	}
	internalBundleCollection := c.addInternalSupportBundleCollection(bundle, nodeSpan, authentication, metav1.NewTime(expiredAt))
	// Process the support bundle collection when time is up, this will create a CollectionFailure condition if the
	// bundle collection is not completed in time because any Agent fails to upload the files and does not report
	// the failure.
	c.queue.AddAfter(bundle.Name, expiredAt.Sub(now))
	klog.InfoS("Created internal SupportBundleCollection", "name", bundle.Name)
	return internalBundleCollection, nil
}

// getBundleNodes returns the names of the Nodes configured in the SupportBundleCollection.
func (c *Controller) getBundleNodes(nodes *v1alpha1.BundleNodes) (sets.Set[string], error) {
	if nodes == nil {
		return sets.New[string](), nil
	}

	// Return all Kubernetes Nodes if NodeNames is empty and NodeSelector is not specified.
	if len(nodes.NodeNames) == 0 && nodes.NodeSelector == nil {
		allNodes, err := c.nodeLister.List(labels.Everything())
		if err != nil {
			return nil, fmt.Errorf("failed to list all Nodes in the cluster: %v", err)
		}
		nodeNames := sets.New[string]()
		for _, n := range allNodes {
			nodeNames.Insert(n.Name)
		}
		return nodeNames, nil
	}

	// Add the Nodes which are configured with the names defined in the resource.
	nodeNames := sets.New[string]()
	for _, name := range nodes.NodeNames {
		_, err := c.nodeLister.Get(name)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("unable to get Node %s: %v", name, err)
		}
		nodeNames.Insert(name)
	}
	// Add the Nodes which are configured with the given label.
	if nodes.NodeSelector != nil {
		nodeSelector, _ := metav1.LabelSelectorAsSelector(nodes.NodeSelector)
		selectedNodes, err := c.nodeLister.List(nodeSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to list Nodes with labels %s: %v", nodeSelector.String(), err)
		}
		for _, n := range selectedNodes {
			nodeNames.Insert(n.Name)
		}
	}
	return nodeNames, nil
}

// getBundleExternalNodes returns the names of the ExternalNodes configured in the SupportBundleCollection.
func (c *Controller) getBundleExternalNodes(en *v1alpha1.BundleExternalNodes) (sets.Set[string], error) {
	if en == nil {
		return sets.New[string](), nil
	}
	// Return all ExternalNodes in the en.Namespace if both NodeNames is empty and NodeSelector is not specified.
	if len(en.NodeNames) == 0 && en.NodeSelector == nil {
		allExternalNodes, err := c.externalNodeLister.ExternalNodes(en.Namespace).List(labels.Everything())
		if err != nil {
			return nil, fmt.Errorf("failed to list all ExternalNodes in the namespace %s: %v", en.Namespace, err)
		}
		enNames := sets.New[string]()
		for _, n := range allExternalNodes {
			enNameKey := k8s.NamespacedName(n.Namespace, n.Name)
			enNames.Insert(enNameKey)
		}
		return enNames, nil
	}

	enNames := sets.New[string]()
	for _, name := range en.NodeNames {
		_, err := c.externalNodeLister.ExternalNodes(en.Namespace).Get(name)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("unable to get existing ExternalNode %s/%s: %v", en.Namespace, name, err)
		}
		enNames.Insert(k8s.NamespacedName(en.Namespace, name))
	}
	if en.NodeSelector != nil {
		nodeSelector, _ := metav1.LabelSelectorAsSelector(en.NodeSelector)
		selectedNodes, err := c.externalNodeLister.ExternalNodes(en.Namespace).List(nodeSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to list ExternalNodes with labels %s in namespace %s: %v", nodeSelector.String(), en.Namespace, err)
		}
		for _, n := range selectedNodes {
			enNames.Insert(k8s.NamespacedName(n.Namespace, n.Name))
		}
	}
	return enNames, nil
}

func (c *Controller) deleteInternalSupportBundleCollection(key string) error {
	_, exists, _ := c.supportBundleCollectionStore.Get(key)
	if !exists {
		klog.InfoS("Internal SupportBundleCollection does not exist", "name", key)
		return nil
	}
	err := c.supportBundleCollectionStore.Delete(key)
	if err != nil {
		klog.ErrorS(err, "Failed to delete internal SupportBundleCollection", "name", key)
		return err
	}
	if obj, exists, _ := c.supportBundleCollectionAppliedToStore.GetByKey(key); exists {
		c.supportBundleCollectionAppliedToStore.Delete(obj)
	}
	c.clearStatuses(key)
	klog.InfoS("Deleted internal SupportBundleCollection", "name", key)
	return nil
}

// parseBundleAuth returns the authentication from the Secret provided in BundleServerAuthConfiguration.
// The authentication is stored in the Secret Data with a key decided by the AuthType, and encoded using base64.
func (c *Controller) parseBundleAuth(authentication v1alpha1.BundleServerAuthConfiguration) (*controlplane.BundleServerAuthConfiguration, error) {
	secretReference := authentication.AuthSecret
	if secretReference == nil {
		return nil, fmt.Errorf("authentication is not specified")
	}
	secret, err := c.kubeClient.CoreV1().Secrets(secretReference.Namespace).Get(context.TODO(), secretReference.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get Secret with name %s in Namespace %s: %v", secretReference.Name, secretReference.Namespace, err)
	}
	parseAuthValue := func(secretData map[string][]byte, key string) (string, error) {
		authValue, found := secret.Data[key]
		if !found {
			return "", fmt.Errorf("not found authentication in Secret %s/%s with key %s", secretReference.Namespace, secretReference.Name, key)
		}
		return bytes.NewBuffer(authValue).String(), nil
	}
	switch authentication.AuthType {
	case v1alpha1.APIKey:
		value, err := parseAuthValue(secret.Data, secretKeyWithAPIKey)
		if err != nil {
			return nil, err
		}
		return &controlplane.BundleServerAuthConfiguration{
			APIKey: value,
		}, nil
	case v1alpha1.BearerToken:
		value, err := parseAuthValue(secret.Data, secretKeyWithBearerToken)
		if err != nil {
			return nil, err
		}
		return &controlplane.BundleServerAuthConfiguration{
			BearerToken: value,
		}, nil
	case v1alpha1.BasicAuthentication:
		username, err := parseAuthValue(secret.Data, secretKeyWithUsername)
		if err != nil {
			return nil, err
		}
		password, err := parseAuthValue(secret.Data, secretKeyWithPassword)
		if err != nil {
			return nil, err
		}
		return &controlplane.BundleServerAuthConfiguration{
			BasicAuthentication: &controlplane.BasicAuthentication{
				Username: username,
				Password: password,
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported authentication type %s", authentication.AuthType)
}

// addInternalSupportBundleCollection adds internalBundle into supportBundleCollectionStore, and creates a
// supportBundleCollectionAppliedTo resource to maintain the SupportBundleCollection's required Nodes or ExternalNodes.
func (c *Controller) addInternalSupportBundleCollection(
	bundleCollection *v1alpha1.SupportBundleCollection,
	nodeSpan sets.Set[string],
	authentication *controlplane.BundleServerAuthConfiguration,
	expiredAt metav1.Time) *types.SupportBundleCollection {
	var processNodes bool
	if bundleCollection.Spec.Nodes == nil {
		processNodes = false
	} else {
		processNodes = true
	}
	var enNamespace string
	if bundleCollection.Spec.ExternalNodes == nil {
		enNamespace = ""
	} else {
		enNamespace = bundleCollection.Spec.ExternalNodes.Namespace
	}

	appliedTo := &supportBundleCollectionAppliedTo{
		name:         bundleCollection.Name,
		processNodes: processNodes,
		enNamespace:  enNamespace,
	}
	c.supportBundleCollectionAppliedToStore.Add(appliedTo)
	// Create internal SupportBundleCollection resource.
	internalBundleCollection := &types.SupportBundleCollection{
		SpanMeta: types.SpanMeta{
			NodeNames: nodeSpan,
		},
		Name:           bundleCollection.Name,
		UID:            bundleCollection.UID,
		SinceTime:      bundleCollection.Spec.SinceTime,
		FileServer:     bundleCollection.Spec.FileServer,
		ExpiredAt:      expiredAt,
		Authentication: *authentication,
	}
	_ = c.supportBundleCollectionStore.Create(internalBundleCollection)
	return internalBundleCollection
}

// processConflictedCollection adds a Started failure condition on the conflicted the SupportBundleCollection request,
// and re-enqueue the request after 10s.
func (c *Controller) processConflictedCollection(bundle *v1alpha1.SupportBundleCollection) error {
	message := "another SupportBundleCollection is processing on Nodes or on ExternalNodes in the same namespace, retry in 10s"
	now := metav1.Now()
	condition := []v1alpha1.SupportBundleCollectionCondition{
		{
			Type:               v1alpha1.CollectionStarted,
			Status:             metav1.ConditionFalse,
			Reason:             string(metav1.StatusReasonConflict),
			Message:            message,
			LastTransitionTime: now,
		},
		{
			Type:               v1alpha1.BundleCollected,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: now,
		},
		{
			Type:               v1alpha1.CollectionFailure,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: now,
		},
		{
			Type:               v1alpha1.CollectionCompleted,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: now,
		},
	}
	if err := c.addConditions(bundle.Name, condition); err != nil {
		klog.ErrorS(err, "Failed to create a Started failed condition")
		return err
	}
	c.queue.AddAfter(bundle.Name, supportBundleCollectionRetryPeriod)
	return nil
}

func (c *Controller) addConditions(bundleCollectionName string, conditions []v1alpha1.SupportBundleCollectionCondition) error {
	if len(conditions) == 0 {
		return nil
	}
	bundleCollection, getErr := c.supportBundleCollectionLister.Get(bundleCollectionName)
	if getErr != nil {
		return getErr
	}
	toUpdate := bundleCollection.DeepCopy()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		updatedConditions := mergeConditions(toUpdate.Status.Conditions, conditions)
		toUpdate.Status.Conditions = updatedConditions
		klog.V(2).InfoS("Updating SupportBundleCollection", "SupportBundleCollection", bundleCollectionName)
		_, updateErr := c.crdClient.CrdV1alpha1().SupportBundleCollections().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && k8serrors.IsConflict(updateErr) {
			if toUpdate, getErr = c.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.TODO(), bundleCollectionName, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		// Return the error from UPDATE.
		return updateErr
	}); err != nil {
		return err
	}
	return nil
}

// isCollectionAvailable checks if the bundleCollection can be processed at once. It returns true with these conditions:
//  1. the bundleCollection is started processing;
//  2. there are no processing SupportBundleCollections requiring to collect bundle files on any Nodes, if this one requires
//     to collection files on Nodes;
//  3. there are no processing SupportBundleCollections requiring to collect bundle files on the ExternalNodes in the same
//     Namespace as this one.
func (c *Controller) isCollectionAvailable(bundleCollection *v1alpha1.SupportBundleCollection) bool {
	_, exists, _ := c.supportBundleCollectionAppliedToStore.GetByKey(bundleCollection.Name)
	if exists {
		return true
	}
	if bundleCollection.Spec.Nodes != nil {
		bundleCollectionsForAllNodes, _ := c.supportBundleCollectionAppliedToStore.ByIndex(processingNodesIndex, processingNodesIndexValue)
		if len(bundleCollectionsForAllNodes) > 0 {
			return false
		}
	}
	if bundleCollection.Spec.ExternalNodes != nil {
		namespace := bundleCollection.Spec.ExternalNodes.Namespace
		bundleCollectionsForExternalNodes, _ := c.supportBundleCollectionAppliedToStore.ByIndex(processingExternalNodesIndex, namespace)
		if len(bundleCollectionsForExternalNodes) > 0 {
			return false
		}
	}
	return true
}

func (c *Controller) updateStatus(internalBundleCollection *types.SupportBundleCollection) error {
	now := metav1.Now()
	desiredNodes := len(internalBundleCollection.SpanMeta.NodeNames)
	collectedNodes := 0
	failedNodeReasons := make(map[string][]string)
	failedNodes := 0
	statuses := c.getNodeStatuses(internalBundleCollection.Name)
	for _, status := range statuses {
		nodeKey := getNodeKey(status)
		// The node is no longer in the span of this Support Bundle Collection, delete its status.
		if !internalBundleCollection.NodeNames.Has(nodeKey) {
			c.deleteNodeStatus(internalBundleCollection.Name, nodeKey)
			continue
		}
		if status.Completed {
			collectedNodes += 1
		} else {
			failedNodes += 1
			failedReason := status.Error
			if failedReason == "" {
				failedReason = "unknown error"
			}
			_, exists := failedNodeReasons[failedReason]
			if !exists {
				failedNodeReasons[failedReason] = make([]string, 0)
			}
			failedNodeReasons[failedReason] = append(failedNodeReasons[failedReason], nodeKey)
		}
	}

	newConditions := []v1alpha1.SupportBundleCollectionCondition{
		// Mark the support bundle collection as started since the internal resource successfully created.
		// It will not be added as a duplication if it already exists.
		{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.Now()},
	}
	bundleCollectedStatus, collectionCompleted := metav1.ConditionFalse, metav1.ConditionFalse
	if collectedNodes > 0 {
		bundleCollectedStatus = metav1.ConditionTrue
	}
	newConditions = append(newConditions,
		v1alpha1.SupportBundleCollectionCondition{
			Type:               v1alpha1.BundleCollected,
			Status:             bundleCollectedStatus,
			LastTransitionTime: now,
		},
	)
	if failedNodes > 0 {
		failedNodeErrors := make([]string, 0, len(failedNodeReasons))
		for k, v := range failedNodeReasons {
			sort.Strings(v)
			failedNodeErrors = append(failedNodeErrors, fmt.Sprintf(`"%s":[%s]`, k, strings.Join(v, ", ")))
		}
		sort.Strings(failedNodeErrors)
		failedConditionMessage := fmt.Sprintf("Failed Agent count: %d, %s", failedNodes, strings.Join(failedNodeErrors, ", "))
		newConditions = append(newConditions,
			v1alpha1.SupportBundleCollectionCondition{
				Type:               v1alpha1.CollectionFailure,
				Status:             metav1.ConditionTrue,
				Reason:             string(metav1.StatusReasonInternalError),
				Message:            failedConditionMessage,
				LastTransitionTime: now,
			},
		)
	} else {
		newConditions = append(newConditions,
			v1alpha1.SupportBundleCollectionCondition{
				Type:               v1alpha1.CollectionFailure,
				Status:             metav1.ConditionFalse,
				LastTransitionTime: now,
			},
		)
	}
	if collectedNodes+failedNodes == desiredNodes {
		collectionCompleted = metav1.ConditionTrue
	}
	newConditions = append(newConditions,
		v1alpha1.SupportBundleCollectionCondition{
			Type:               v1alpha1.CollectionCompleted,
			Status:             collectionCompleted,
			LastTransitionTime: now,
		},
	)
	status := &v1alpha1.SupportBundleCollectionStatus{
		CollectedNodes: int32(collectedNodes),
		DesiredNodes:   int32(desiredNodes),
		Conditions:     newConditions,
	}
	klog.V(2).InfoS("Updating SupportBundleCollection status", "supportBundleCollection", internalBundleCollection.Name, "status", status)
	return c.updateSupportBundleCollectionStatus(internalBundleCollection.Name, status)
}

func (c *Controller) getNodeStatuses(key string) []*controlplane.SupportBundleCollectionNodeStatus {
	c.statusesLock.RLock()
	defer c.statusesLock.RUnlock()
	statusPerNode, exists := c.statuses[key]
	if !exists {
		return nil
	}
	statuses := make([]*controlplane.SupportBundleCollectionNodeStatus, 0, len(c.statuses[key]))
	for _, status := range statusPerNode {
		statuses = append(statuses, status)
	}
	return statuses
}

func (c *Controller) deleteNodeStatus(key string, nodeName string) {
	c.statusesLock.Lock()
	defer c.statusesLock.Unlock()
	statusPerNode, exists := c.statuses[key]
	if !exists {
		return
	}
	delete(statusPerNode, nodeName)
}

func (c *Controller) clearStatuses(key string) {
	c.statusesLock.Lock()
	defer c.statusesLock.Unlock()
	delete(c.statuses, key)
}

func (c *Controller) updateSupportBundleCollectionStatus(name string, updatedStatus *v1alpha1.SupportBundleCollectionStatus) error {
	bundleCollection, err := c.supportBundleCollectionLister.Get(name)
	if err != nil {
		klog.InfoS("Didn't find the original SupportBundleCollection, skip updating status", "supportBundleCollection", name)
		return nil
	}
	toUpdate := bundleCollection.DeepCopy()
	if err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		updatedConditions := mergeConditions(toUpdate.Status.Conditions, updatedStatus.Conditions)
		updatedStatus.Conditions = updatedConditions
		// If the current status equals to the desired status, no need to update.
		if supportBundleCollectionStatusEqual(toUpdate.Status, *updatedStatus) {
			return nil
		}
		toUpdate.Status = *updatedStatus
		klog.V(2).InfoS("Updating SupportBundleCollection", "supportBundleCollection", name)
		_, updateErr := c.crdClient.CrdV1alpha1().SupportBundleCollections().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && k8serrors.IsConflict(updateErr) {
			var getErr error
			if toUpdate, getErr = c.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.TODO(), name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		// Return the error from UPDATE.
		return updateErr
	}); err != nil {
		return err
	}
	klog.V(2).InfoS("Updated SupportBundleCollection", "supportBundleCollection", name)
	return nil
}

// isCollectionCompleted check if CollectionCompleted condition with status ConditionTrue is added in the bundleCollection or not.
func isCollectionCompleted(bundleCollection *v1alpha1.SupportBundleCollection) bool {
	for _, condition := range bundleCollection.Status.Conditions {
		if condition.Type == v1alpha1.CollectionCompleted && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// isCollectionProcessing check if CollectionStarted condition with status ConditionTrue is added in the bundleCollection or not.
func isCollectionProcessing(bundleCollection *v1alpha1.SupportBundleCollection) bool {
	if isCollectionCompleted(bundleCollection) {
		return false
	}
	for _, c := range bundleCollection.Status.Conditions {
		if c.Type == v1alpha1.CollectionStarted && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func conditionEqualsIgnoreLastTransitionTime(a, b v1alpha1.SupportBundleCollectionCondition) bool {
	a1 := a
	a1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	b1 := b
	b1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return a1 == b1
}

func conditionExistsIgnoreLastTransitionTime(conditions []v1alpha1.SupportBundleCollectionCondition, condition v1alpha1.SupportBundleCollectionCondition) bool {
	for _, c := range conditions {
		if conditionEqualsIgnoreLastTransitionTime(c, condition) {
			return true
		}
	}
	return false
}

func mergeConditions(oldConditions, newConditions []v1alpha1.SupportBundleCollectionCondition) []v1alpha1.SupportBundleCollectionCondition {
	finalConditions := make([]v1alpha1.SupportBundleCollectionCondition, 0)
	newConditionMap := make(map[v1alpha1.SupportBundleCollectionConditionType]v1alpha1.SupportBundleCollectionCondition)
	addedConditions := sets.New[string]()
	for _, condition := range newConditions {
		newConditionMap[condition.Type] = condition
	}
	for _, oldCondition := range oldConditions {
		newCondition, exists := newConditionMap[oldCondition.Type]
		if !exists {
			finalConditions = append(finalConditions, oldCondition)
			continue
		}
		// Use the original Condition if the only change is about lastTransition time
		if conditionEqualsIgnoreLastTransitionTime(newCondition, oldCondition) {
			finalConditions = append(finalConditions, oldCondition)
		} else {
			// Use the latest Condition.
			finalConditions = append(finalConditions, newCondition)
		}
		addedConditions.Insert(string(newCondition.Type))
	}
	for key, newCondition := range newConditionMap {
		if !addedConditions.Has(string(key)) {
			finalConditions = append(finalConditions, newCondition)
		}
	}
	return finalConditions
}

func getNodeKey(status *controlplane.SupportBundleCollectionNodeStatus) string {
	if status.NodeType == controlplane.SupportBundleCollectionNodeTypeExternalNode {
		return k8s.NamespacedName(status.NodeNamespace, status.NodeName)
	}
	return status.NodeName
}

var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	conditionSliceEqualsIgnoreLastTransitionTime,
)

// supportBundleCollectionStatusEqual compares two SupportBundleCollectionStatus objects. It disregards
// the LastTransitionTime field in the status Conditions.
func supportBundleCollectionStatusEqual(oldStatus, newStatus v1alpha1.SupportBundleCollectionStatus) bool {
	return semanticIgnoreLastTransitionTime.DeepEqual(oldStatus, newStatus)
}

func conditionSliceEqualsIgnoreLastTransitionTime(as, bs []v1alpha1.SupportBundleCollectionCondition) bool {
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		a := as[i]
		b := bs[i]
		if !conditionEqualsIgnoreLastTransitionTime(a, b) {
			return false
		}
	}
	return true
}
