/*
Copyright 2021 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package multicluster

import (
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/core"
)

// StaleController will clean up ServiceImport and MC Service if no corresponding ResourceImport
// in the leader cluster and remove any ResourceExport in the leader cluster if no correspoding
// ServiceExport in the member cluster. It will only run in the member cluster.
type StaleController struct {
	client.Client
	Scheme                  *runtime.Scheme
	remoteCommonAreaManager *core.RemoteCommonAreaManager
	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
}

func NewStaleController(
	Client client.Client,
	Scheme *runtime.Scheme,
	remoteCommonAreaManager *core.RemoteCommonAreaManager) *StaleController {
	reconciler := &StaleController{
		Client:                  Client,
		Scheme:                  Scheme,
		remoteCommonAreaManager: remoteCommonAreaManager,
		queue:                   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "StaleController"),
	}
	return reconciler
}

//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;delete
//+kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceimports,verbs=get;list;watch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports,verbs=get;list;watch;
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;delete

func (c *StaleController) cleanup() error {
	if *c.remoteCommonAreaManager == nil {
		return errors.New("ClusterSet has not been initialized properly, no available remote common area")
	}

	remoteCluster, err := getRemoteCommonArea(c.remoteCommonAreaManager)
	if err != nil {
		return err
	}

	localClusterID := string((*c.remoteCommonAreaManager).GetLocalClusterID())
	if len(localClusterID) == 0 {
		return errors.New("localClusterID is not initialized, retry later")
	}

	svcImpList := &k8smcsv1alpha1.ServiceImportList{}
	if err := c.List(ctx, svcImpList, &client.ListOptions{}); err != nil {
		return err
	}

	svcList := &corev1.ServiceList{}
	if err := c.List(ctx, svcList, &client.ListOptions{}); err != nil {
		return err
	}

	resImpList := &mcsv1alpha1.ResourceImportList{}
	if err := remoteCluster.List(ctx, resImpList, &client.ListOptions{Namespace: remoteCluster.GetNamespace()}); err != nil {
		return err
	}

	svcImpItems := svcImpList.Items
	var mcsSvcItems []corev1.Service
	for _, svc := range svcList.Items {
		if _, ok := svc.Annotations[common.AntreaMCServiceAnnotation]; ok {
			mcsSvcItems = append(mcsSvcItems, svc)
		}
	}

	for _, resImp := range resImpList.Items {
		for k, svc := range mcsSvcItems {
			if svc.Name == common.AntreaMCSPrefix+resImp.Spec.Name && svc.Namespace == resImp.Spec.Namespace {
				// Set the valid Service item as empty Service, then all left non-empty items should be removed.
				mcsSvcItems[k] = corev1.Service{}
			}
		}

		for n, svcImp := range svcImpItems {
			if svcImp.Name == resImp.Spec.Name && svcImp.Namespace == resImp.Spec.Namespace {
				svcImpItems[n] = k8smcsv1alpha1.ServiceImport{}
			}
		}
	}

	for _, svc := range mcsSvcItems {
		s := svc
		if s.Name != "" {
			klog.InfoS("clean up Service", "service", klog.KObj(&s))
			if err := c.Client.Delete(ctx, &s, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	for _, svcImp := range svcImpItems {
		si := svcImp
		if si.Name != "" {
			klog.InfoS("clean up ServiceImport", "serviceimport", klog.KObj(&si))
			if err = c.Client.Delete(ctx, &si, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	// clean up any ResourceExport if no corresponding ServiceExport locally
	resExpList := &mcsv1alpha1.ResourceExportList{}
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			common.SourceClusterID: localClusterID,
		},
	}
	selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
	if err := remoteCluster.List(ctx, resExpList, &client.ListOptions{Namespace: remoteCluster.GetNamespace(), LabelSelector: selector}); err != nil {
		return err
	}
	svcExpList := &k8smcsv1alpha1.ServiceExportList{}
	if err := c.List(ctx, svcExpList, &client.ListOptions{}); err != nil {
		return err
	}
	resExpItems := resExpList.Items
	svcExpItems := svcExpList.Items

	for k, re := range resExpItems {
		for _, se := range svcExpItems {
			if re.Spec.Name == se.Name && re.Spec.Namespace == se.Namespace {
				// Set the valid ResourceExport item as empty ResourceExport, then all left non-empty items should be removed.
				resExpItems[k] = mcsv1alpha1.ResourceExport{}
			}
		}
	}

	for _, r := range resExpItems {
		re := r
		if re.Name != "" {
			klog.InfoS("clean up ResourceExport", "ResourceExport", klog.KObj(&re))
			if err := remoteCluster.Delete(ctx, &re, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

// Enqueue will be called after StaleController is initialized.
func (c *StaleController) Enqueue() {
	// The key can be anything as we only have single item.
	c.queue.Add("key")
}

// Run starts the StaleController and blocks until stopCh is closed.
// it will run only once to clean up stale resources if no error happens.
func (c *StaleController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting StaleController")
	defer klog.InfoS("Shutting down StaleController")

	if err := c.RunOnce(); err != nil {
		c.Enqueue()
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *StaleController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *StaleController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.cleanup()
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	klog.ErrorS(err, "Error removing stale ServiceImport or multi-cluster Service, requeuing it")
	c.queue.AddRateLimited(key)
	return true
}

func (c *StaleController) RunOnce() error {
	err := c.cleanup()
	if err != nil {
		return err
	}
	return nil
}

// We should have only one remote common area at this moment,
// so check and return the first common area.
func getRemoteCommonArea(remoteMgr *core.RemoteCommonAreaManager) (core.RemoteCommonArea, error) {
	var remoteCommonArea core.RemoteCommonArea
	remoteCommonAreas := (*remoteMgr).GetRemoteCommonAreas()
	if len(remoteCommonAreas) <= 0 {
		return nil, errors.New("ClusterSet has not been initialized properly, no remote common area manager")
	}

	for _, c := range remoteCommonAreas {
		if c.IsConnected() {
			remoteCommonArea = c
			break
		}
	}
	if remoteCommonArea != nil {
		return remoteCommonArea, nil
	} else {
		return nil, errors.New("no connected remote common area")
	}
}
