// Copyright 2020 Antrea Authors
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

package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	informerv1alpha1 "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	listerv1alpha1 "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	controllerquerier "antrea.io/antrea/pkg/controller/querier"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	crdName        = "antrea-controller"
	controllerName = "AntreaControllerMonitor"

	// How long to wait before retrying the processing of an AccountNodeMapping change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing AccountNodeMapping changes.
	defaultWorkers = 4
)

type ControllerMonitor struct {
	client       clientset.Interface
	nodeInformer coreinformers.NodeInformer
	// nodeListerSynced is a function which returns true if the node shared informer has been synced at least once.
	nodeListerSynced cache.InformerSynced
	querier          controllerquerier.ControllerQuerier
	// controllerCRD is the desired state of controller monitoring CRD which controllerMonitor expects.
	controllerCRD   *v1beta1.AntreaControllerInfo
	anmInformer     informerv1alpha1.AccountNodeMappingInformer
	anmLister       listerv1alpha1.AccountNodeMappingLister
	anmListerSynced cache.InformerSynced
	anmQueue        workqueue.RateLimitingInterface
	anmStore        cache.Store
}

// NewControllerMonitor creates a new controller monitor.
func NewControllerMonitor(
	client clientset.Interface,
	nodeInformer coreinformers.NodeInformer,
	querier controllerquerier.ControllerQuerier,
	anmInformer informerv1alpha1.AccountNodeMappingInformer,
) *ControllerMonitor {
	m := &ControllerMonitor{
		client:           client,
		nodeInformer:     nodeInformer,
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		querier:          querier,
		controllerCRD:    nil,
		anmInformer:      anmInformer,
		anmLister:        anmInformer.Lister(),
		anmListerSynced:  anmInformer.Informer().HasSynced,
		anmQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "accountNodeMapping"),
		anmStore:         cache.NewStore(cache.MetaNamespaceKeyFunc),
	}
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    nil,
		UpdateFunc: nil,
		DeleteFunc: m.deleteStaleAgentCRD,
	})
	anmInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: m.enqueueMapping,
		UpdateFunc: func(oldObj, newObj interface{}) {
			m.enqueueMapping(newObj)
		},
		DeleteFunc: m.enqueueMapping,
	})
	return m
}

func (monitor *ControllerMonitor) enqueueMapping(obj interface{}) {
	anm := obj.(*v1alpha1.AccountNodeMapping)
	klog.InfoS("Enqueuing AccountNodeMapping", "AccountNodeMapping", klog.KObj(anm))
	key := k8s.NamespacedName(anm.Namespace, anm.Name)
	monitor.anmQueue.Add(key)
}

// Run creates AntreaControllerInfo CRD first after controller is running.
// Then updates AntreaControllerInfo CRD every 60 seconds if there is any change.
func (monitor *ControllerMonitor) Run(stopCh <-chan struct{}) {
	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, monitor.nodeListerSynced, monitor.anmListerSynced) {
		return
	}

	monitor.deleteStaleAgentCRDs()

	// Sync controller monitoring CRD every minute util stopCh is closed.
	go wait.Until(monitor.syncControllerCRD, time.Minute, stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(monitor.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (monitor *ControllerMonitor) worker() {
	for monitor.processMapping() {
	}
}

func (monitor *ControllerMonitor) processMapping() bool {
	key, quit := monitor.anmQueue.Get()
	if quit {
		return false
	}
	defer monitor.anmQueue.Done(key)

	err := monitor.syncMapping(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		monitor.anmQueue.AddRateLimited(key)
		klog.Errorf("Failed to sync  %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	monitor.anmQueue.Forget(key)
	return true
}

func (monitor *ControllerMonitor) syncMapping(key string) error {
	namespace, name := k8s.SplitNamespacedName(key)
	anm, err := monitor.anmLister.AccountNodeMappings(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			item, exist, _ := monitor.anmStore.GetByKey(key)
			if exist {
				monitor.anmStore.Delete(item)
			}
			return nil
		} else {
			return err
		}
	}
	_, found, _ := monitor.anmStore.GetByKey(key)
	if found {
		monitor.anmStore.Update(anm)
	} else {
		monitor.anmStore.Add(anm)
	}
	return nil
}

func (monitor *ControllerMonitor) syncControllerCRD() {
	var err error
	if monitor.controllerCRD != nil {
		if monitor.controllerCRD, err = monitor.updateControllerCRD(true); err == nil {
			return
		}
		klog.Errorf("Failed to partially update controller monitoring CRD: %v", err)
		monitor.controllerCRD = nil
	}

	monitor.controllerCRD, err = monitor.getControllerCRD(crdName)

	if errors.IsNotFound(err) {
		monitor.controllerCRD, err = monitor.createControllerCRD(crdName)
		if err != nil {
			klog.Errorf("Failed to create controller monitoring CRD: %v", err)
			monitor.controllerCRD = nil
		}
		return
	}

	if err != nil {
		klog.Errorf("Failed to get controller monitoring CRD: %v", err)
		monitor.controllerCRD = nil
		return
	}

	monitor.controllerCRD, err = monitor.updateControllerCRD(false)
	if err != nil {
		klog.Errorf("Failed to entirely update controller monitoring CRD: %v", err)
		monitor.controllerCRD = nil
	}
}

// getControllerCRD is used to check the existence of controller monitoring CRD.
// So when the Pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *ControllerMonitor) getControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

func (monitor *ControllerMonitor) createControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD := new(v1beta1.AntreaControllerInfo)
	controllerCRD.Name = crdName
	monitor.querier.GetControllerInfo(controllerCRD, false)
	klog.V(2).Infof("Creating controller monitoring CRD %+v", controllerCRD)
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Create(context.TODO(), controllerCRD, metav1.CreateOptions{})
}

// updateControllerCRD updates the monitoring CRD.
func (monitor *ControllerMonitor) updateControllerCRD(partial bool) (*v1beta1.AntreaControllerInfo, error) {
	monitor.querier.GetControllerInfo(monitor.controllerCRD, partial)
	klog.V(2).Infof("Updating controller monitoring CRD %+v, partial: %t", monitor.controllerCRD, partial)
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Update(context.TODO(), monitor.controllerCRD, metav1.UpdateOptions{})
}

func (monitor *ControllerMonitor) deleteStaleAgentCRDs() {
	crds, err := monitor.client.CrdV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{
		ResourceVersion: "0",
	})
	if err != nil {
		klog.Errorf("Failed to list agent monitoring CRDs: %v", err)
		return
	}
	// Delete stale agent monitoring CRD based on existing nodes.
	nodeLister := monitor.nodeInformer.Lister()
	for _, crd := range crds.Items {
		_, err := nodeLister.Get(crd.Name)
		if errors.IsNotFound(err) {
			monitor.deleteAgentCRD(crd.Name)
		}
	}
}

func (monitor *ControllerMonitor) deleteStaleAgentCRD(old interface{}) {
	node, ok := old.(*corev1.Node)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Node, invalid type: %v", old)
			return
		}
		node, ok = tombstone.Obj.(*corev1.Node)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Node, invalid type: %v", tombstone.Obj)
			return
		}
	}
	monitor.deleteAgentCRD(node.Name)
}

func (monitor *ControllerMonitor) deleteAgentCRD(name string) {
	klog.Infof("Deleting agent monitoring CRD %s", name)
	err := monitor.client.CrdV1beta1().AntreaAgentInfos().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		klog.Errorf("Failed to delete agent monitoring CRD %s: %v", name, err)
	}
}

func (monitor *ControllerMonitor) ValidateAntreaAgentInfo(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := true

	if review.Request.Operation == admv1.Create || review.Request.Operation == admv1.Update {
		var newObj v1beta1.AntreaAgentInfo
		if review.Request.Object.Raw != nil {
			if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
				klog.ErrorS(err, "Error de-serializing current AntreaAgentInfo")
				return getAdmissionResponseForErr(err)
			}
		}

		userName := review.Request.UserInfo.Username
		if serviceaccount.MatchesUsername("kube-system", "antrea-agent", userName) {
			allowed = true
		} else {
			namespace, name, err := serviceaccount.SplitUsername(userName)
			if err != nil {
				klog.ErrorS(err, "Error splitting UserName", "UserName", userName)
				return getAdmissionResponseForErr(err)
			}
			obj, exist, _ := monitor.anmStore.GetByKey(k8s.NamespacedName(namespace, name))
			if !exist {
				err := fmt.Errorf("failed to find AccountNodeMapping account %s, namespace %s", namespace, namespace)
				return getAdmissionResponseForErr(err)
			} else {
				anm := obj.(*v1alpha1.AccountNodeMapping)
				externalNodeDeclared := false
				for _, node := range anm.ExternalNodes {
					if node == newObj.Name {
						externalNodeDeclared = true
						break
					}
				}
				if !externalNodeDeclared {
					allowed = false
					msg = fmt.Sprintf("AccountNodeMapping %s under namespace %s doesn't contain ExternalNode %s", name, namespace, newObj.Name)
				}
			}
		}

	}

	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	return &admv1.AdmissionResponse{
		Allowed: allowed,
		Result:  result,
	}
}

// getAdmissionResponseForErr returns an object of type AdmissionResponse with
// the submitted error message.
func getAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
