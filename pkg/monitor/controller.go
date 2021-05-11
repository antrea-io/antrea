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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/apis/crd/v1beta1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	controllerquerier "github.com/vmware-tanzu/antrea/pkg/controller/querier"
	legacyv1beta1 "github.com/vmware-tanzu/antrea/pkg/legacyapis/clusterinformation/v1beta1"
	legacyclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
)

const (
	crdName        = "antrea-controller"
	controllerName = "AntreaControllerMonitor"
)

type controllerMonitor struct {
	client       clientset.Interface
	legacyClient legacyclientset.Interface
	nodeInformer coreinformers.NodeInformer
	// nodeListerSynced is a function which returns true if the node shared informer has been synced at least once.
	nodeListerSynced cache.InformerSynced
	querier          controllerquerier.ControllerQuerier
	// controllerCRD is the desired state of controller monitoring CRD which controllerMonitor expects.
	controllerCRD       *v1beta1.AntreaControllerInfo
	legacyControllerCRD *legacyv1beta1.AntreaControllerInfo
}

// NewControllerMonitor creates a new controller monitor.
func NewControllerMonitor(client clientset.Interface,
	legacyClient legacyclientset.Interface,
	nodeInformer coreinformers.NodeInformer,
	querier controllerquerier.ControllerQuerier) *controllerMonitor {
	m := &controllerMonitor{
		client:              client,
		legacyClient:        legacyClient,
		nodeInformer:        nodeInformer,
		nodeListerSynced:    nodeInformer.Informer().HasSynced,
		querier:             querier,
		controllerCRD:       nil,
		legacyControllerCRD: nil,
	}
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    nil,
		UpdateFunc: nil,
		DeleteFunc: m.deleteStaleAgentCRD,
	})
	return m
}

// Run creates AntreaControllerInfo CRD first after controller is running.
// Then updates AntreaControllerInfo CRD every 60 seconds if there is any change.
func (monitor *controllerMonitor) Run(stopCh <-chan struct{}) {
	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, monitor.nodeListerSynced) {
		return
	}

	monitor.deleteStaleAgentCRDs()
	monitor.deleteLegacyStaleAgentCRDs()

	// Sync controller monitoring CRD every minute util stopCh is closed.
	wait.Until(monitor.syncControllerCRD, time.Minute, stopCh)

	// Sync legacy controller monitoring CRD every minute util stopCh is closed.
	wait.Until(monitor.syncLegacyControllerCRD, time.Minute, stopCh)
}

func (monitor *controllerMonitor) syncControllerCRD() {
	var err error = nil
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
func (monitor *controllerMonitor) getControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

func (monitor *controllerMonitor) createControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD := new(v1beta1.AntreaControllerInfo)
	controllerCRD.Name = crdName
	monitor.querier.GetControllerInfo(controllerCRD, false)
	klog.V(2).Infof("Creating controller monitoring CRD %+v", controllerCRD)
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Create(context.TODO(), controllerCRD, metav1.CreateOptions{})
}

// updateControllerCRD updates the monitoring CRD.
func (monitor *controllerMonitor) updateControllerCRD(partial bool) (*v1beta1.AntreaControllerInfo, error) {
	monitor.querier.GetControllerInfo(monitor.controllerCRD, partial)
	klog.V(2).Infof("Updating controller monitoring CRD %+v, partial: %t", monitor.controllerCRD, partial)
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Update(context.TODO(), monitor.controllerCRD, metav1.UpdateOptions{})
}

func (monitor *controllerMonitor) deleteStaleAgentCRDs() {
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

func (monitor *controllerMonitor) deleteStaleAgentCRD(old interface{}) {
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
	monitor.deleteLegacyAgentCRD(node.Name)
}

func (monitor *controllerMonitor) deleteAgentCRD(name string) {
	klog.Infof("Deleting agent monitoring CRD %s", name)
	err := monitor.client.CrdV1beta1().AntreaAgentInfos().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		klog.Errorf("Failed to delete agent monitoring CRD %s: %v", name, err)
	}
}

func (monitor *controllerMonitor) syncLegacyControllerCRD() {
	var err error = nil
	if monitor.legacyControllerCRD != nil {
		if monitor.legacyControllerCRD, err = monitor.updateLegacyControllerCRD(true); err == nil {
			return
		}
		klog.Errorf("Failed to partially update legacy controller monitoring CRD: %v", err)
		monitor.legacyControllerCRD = nil
	}

	monitor.legacyControllerCRD, err = monitor.getLegacyControllerCRD(crdName)

	if errors.IsNotFound(err) {
		monitor.legacyControllerCRD, err = monitor.createLegacyControllerCRD(crdName)
		if err != nil {
			klog.Errorf("Failed to create legacy controller monitoring CRD: %v", err)
			monitor.legacyControllerCRD = nil
		}
		return
	}

	if err != nil {
		klog.Errorf("Failed to get legacy controller monitoring CRD: %v", err)
		monitor.legacyControllerCRD = nil
		return
	}

	monitor.legacyControllerCRD, err = monitor.updateLegacyControllerCRD(false)
	if err != nil {
		klog.Errorf("Failed to entirely update legacy controller monitoring CRD: %v", err)
		monitor.legacyControllerCRD = nil
	}
}

func (monitor *controllerMonitor) getLegacyControllerCRD(crdName string) (*legacyv1beta1.AntreaControllerInfo, error) {
	return monitor.legacyClient.ClusterinformationV1beta1().AntreaControllerInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

func (monitor *controllerMonitor) createLegacyControllerCRD(crdName string) (*legacyv1beta1.AntreaControllerInfo, error) {
	controllerCRD := new(v1beta1.AntreaControllerInfo)
	controllerCRD.Name = crdName
	monitor.querier.GetControllerInfo(controllerCRD, false)
	legacyControllerCRD := controllerInfoDeepCopy(controllerCRD)
	klog.V(2).Infof("Creating legacy controller monitoring CRD %+v", legacyControllerCRD)
	return monitor.legacyClient.ClusterinformationV1beta1().AntreaControllerInfos().Create(context.TODO(), legacyControllerCRD, metav1.CreateOptions{})
}

func (monitor *controllerMonitor) updateLegacyControllerCRD(partial bool) (*legacyv1beta1.AntreaControllerInfo, error) {
	monitor.querier.GetControllerInfo(monitor.controllerCRD, partial)
	monitor.legacyControllerCRD = controllerInfoDeepCopy(monitor.controllerCRD)
	klog.V(2).Infof("Updating controller monitoring CRD %+v, partial: %t", monitor.legacyControllerCRD, partial)
	return monitor.legacyClient.ClusterinformationV1beta1().AntreaControllerInfos().Update(context.TODO(), monitor.legacyControllerCRD, metav1.UpdateOptions{})
}

func (monitor *controllerMonitor) deleteLegacyStaleAgentCRDs() {
	crds, err := monitor.legacyClient.ClusterinformationV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{
		ResourceVersion: "0",
	})
	if err != nil {
		klog.Errorf("Failed to list legacy agent monitoring CRDs: %v", err)
		return
	}

	nodeLister := monitor.nodeInformer.Lister()
	for _, crd := range crds.Items {
		_, err := nodeLister.Get(crd.Name)
		if errors.IsNotFound(err) {
			monitor.deleteLegacyAgentCRD(crd.Name)
		}
	}
}

func (monitor *controllerMonitor) deleteLegacyAgentCRD(name string) {
	klog.Infof("Deleting legacy agent monitoring CRD %s", name)
	err := monitor.legacyClient.ClusterinformationV1beta1().AntreaAgentInfos().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		klog.Errorf("Failed to delete legacy agent monitoring CRD %s: %v", name, err)
	}
}

func controllerInfoDeepCopy(ac *v1beta1.AntreaControllerInfo) *legacyv1beta1.AntreaControllerInfo {
	lac := new(legacyv1beta1.AntreaControllerInfo)
	lac.Name = ac.Name
	lac.Version = ac.Version
	lac.PodRef = *ac.PodRef.DeepCopy()
	lac.NodeRef = *ac.NodeRef.DeepCopy()
	lac.ServiceRef = *ac.ServiceRef.DeepCopy()
	lac.NetworkPolicyControllerInfo = *ac.NetworkPolicyControllerInfo.DeepCopy()
	lac.ConnectedAgentNum = ac.ConnectedAgentNum
	lac.ControllerConditions = []v1beta1.ControllerCondition{}
	for _, cc := range ac.ControllerConditions {
		lac.ControllerConditions = append(lac.ControllerConditions, *cc.DeepCopy())
	}
	lac.APIPort = ac.APIPort
	return lac
}
