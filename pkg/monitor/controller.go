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
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	controllerquerier "github.com/vmware-tanzu/antrea/pkg/controller/querier"
)

type controllerMonitor struct {
	client       clientset.Interface
	nodeInformer coreinformers.NodeInformer
	// nodeListerSynced is a function which returns true if the node shared informer has been synced at least once.
	nodeListerSynced cache.InformerSynced
	querier          controllerquerier.ControllerQuerier
}

// NewControllerMonitor creates a new controller monitor.
func NewControllerMonitor(client clientset.Interface, nodeInformer coreinformers.NodeInformer, querier controllerquerier.ControllerQuerier) *controllerMonitor {
	m := &controllerMonitor{client: client, nodeInformer: nodeInformer, nodeListerSynced: nodeInformer.Informer().HasSynced, querier: querier}
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
	crdName := "antrea-controller"

	// Initialize controller monitoring CRD.
	controllerCRD := monitor.getControllerCRD(crdName)
	var err error = nil
	if controllerCRD == nil {
		controllerCRD, err = monitor.createControllerCRD(crdName)
		if err != nil {
			klog.Errorf("Failed to create controller monitoring CRD %+v: %v", controllerCRD, err)
			return
		}
	} else {
		controllerCRD, err = monitor.updateControllerCRD(controllerCRD)
		if err != nil {
			klog.Errorf("Failed to update controller monitoring CRD %+v: %v", controllerCRD, err)
			return
		}
	}

	klog.Info("Waiting for node synced for Controller Monitor")
	if !cache.WaitForCacheSync(stopCh, monitor.nodeListerSynced) {
		klog.Error("Unable to sync node for Controller Monitor")
		return
	}
	klog.Info("Caches are synced for Controller Monitor")
	monitor.deleteStaleAgentCRDs()

	// Update controller monitoring CRD variables every 60 seconds util stopCh is closed.
	wait.PollUntil(60*time.Second, func() (done bool, err error) {
		controllerCRD, err = monitor.partialUpdateControllerCRD(controllerCRD)
		if err != nil {
			klog.Errorf("Failed to partially update controller monitoring CRD %+v: %v", controllerCRD, err)
		}
		return false, nil
	}, stopCh)
}

// getControllerCRD is used to check the existence of controller monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *controllerMonitor) getControllerCRD(crdName string) *v1beta1.AntreaControllerInfo {
	controllerCRD, err := monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Get(crdName, metav1.GetOptions{})
	if err != nil {
		klog.V(2).Infof("Controller monitoring CRD named %s doesn't exist, will create one", crdName)
		return nil
	}
	return controllerCRD
}

func (monitor *controllerMonitor) createControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD := new(v1beta1.AntreaControllerInfo)
	monitor.querier.GetControllerInfo(controllerCRD, false)
	controllerCRD.ObjectMeta.Name = crdName
	klog.V(2).Infof("Creating controller monitoring CRD %+v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Create(controllerCRD)
}

// updateControllerCRD updates all the fields of existing monitoring CRD.
func (monitor *controllerMonitor) updateControllerCRD(controllerCRD *v1beta1.AntreaControllerInfo) (*v1beta1.AntreaControllerInfo, error) {
	monitor.querier.GetControllerInfo(controllerCRD, false)
	klog.V(2).Infof("Updating controller monitoring CRD %+v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Update(controllerCRD)
}

// partialUpdateControllerCRD only updates the variables.
func (monitor *controllerMonitor) partialUpdateControllerCRD(controllerCRD *v1beta1.AntreaControllerInfo) (*v1beta1.AntreaControllerInfo, error) {
	monitor.querier.GetControllerInfo(controllerCRD, true)
	klog.V(2).Infof("Partially updating controller monitoring CRD %+v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Update(controllerCRD)
}

func (monitor *controllerMonitor) deleteStaleAgentCRDs() {
	crds, err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().List(metav1.ListOptions{})
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
	err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Delete(name, &metav1.DeleteOptions{})
	if err != nil {
		klog.Errorf("Failed to delete agent monitoring CRD %s: %v", name, err)
	}
}
