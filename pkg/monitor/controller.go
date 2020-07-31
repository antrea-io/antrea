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

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	controllerquerier "github.com/vmware-tanzu/antrea/pkg/controller/querier"
)

const crdName = "antrea-controller"

type controllerMonitor struct {
	client       clientset.Interface
	nodeInformer coreinformers.NodeInformer
	// nodeListerSynced is a function which returns true if the node shared informer has been synced at least once.
	nodeListerSynced cache.InformerSynced
	querier          controllerquerier.ControllerQuerier
	// controllerCRD is the desired state of controller monitoring CRD which controllerMonitor expects.
	controllerCRD *v1beta1.AntreaControllerInfo
}

// NewControllerMonitor creates a new controller monitor.
func NewControllerMonitor(client clientset.Interface, nodeInformer coreinformers.NodeInformer, querier controllerquerier.ControllerQuerier) *controllerMonitor {
	m := &controllerMonitor{client: client, nodeInformer: nodeInformer, nodeListerSynced: nodeInformer.Informer().HasSynced, querier: querier, controllerCRD: nil}
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
	klog.Info("Starting Antrea Controller Monitor")

	klog.Info("Waiting for node synced for Controller Monitor")
	if !cache.WaitForCacheSync(stopCh, monitor.nodeListerSynced) {
		klog.Error("Unable to sync node for Controller Monitor")
		return
	}
	klog.Info("Caches are synced for Controller Monitor")
	monitor.deleteStaleAgentCRDs()

	// Sync controller monitoring CRD every minute util stopCh is closed.
	wait.Until(monitor.syncControllerCRD, time.Minute, stopCh)
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
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *controllerMonitor) getControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

func (monitor *controllerMonitor) createControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD := new(v1beta1.AntreaControllerInfo)
	controllerCRD.Name = crdName
	monitor.querier.GetControllerInfo(controllerCRD, false)
	klog.V(2).Infof("Creating controller monitoring CRD %+v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Create(context.TODO(), controllerCRD, metav1.CreateOptions{})
}

// updateControllerCRD updates the monitoring CRD.
func (monitor *controllerMonitor) updateControllerCRD(partial bool) (*v1beta1.AntreaControllerInfo, error) {
	monitor.querier.GetControllerInfo(monitor.controllerCRD, partial)
	klog.V(2).Infof("Updating controller monitoring CRD %+v, partial: %t", monitor.controllerCRD, partial)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Update(context.TODO(), monitor.controllerCRD, metav1.UpdateOptions{})
}

func (monitor *controllerMonitor) deleteStaleAgentCRDs() {
	crds, err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{})
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
	node, ok := old.(*v1.Node)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Node, invalid type: %v", old)
			return
		}
		node, ok = tombstone.Obj.(*v1.Node)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Node, invalid type: %v", tombstone.Obj)
			return
		}
	}
	monitor.deleteAgentCRD(node.Name)
}

func (monitor *controllerMonitor) deleteAgentCRD(name string) {
	klog.Infof("Deleting agent monitoring CRD %s", name)
	err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		klog.Errorf("Failed to delete agent monitoring CRD %s: %v", name, err)
	}
}
