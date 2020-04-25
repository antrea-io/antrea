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

package networkpolicy

import (
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	crdv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1beta1"
)

// addCNP receives ClusterNetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) addCNP(obj interface{}) {
	cnp := obj.(*crdv1beta1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s ADD event", cnp.Name)
}

// updateCNP receives ClusterNetworkPolicy UPDATE events and updates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) updateCNP(oldObj, curObj interface{}) {
	curCNP := curObj.(*crdv1beta1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s UPDATE event", curCNP.Name)
}

// deleteCNP receives ClusterNetworkPolicy DELETED events and deletes resources
// which can be consumed by agents to delete corresponding rules on the Nodes.
func (n *NetworkPolicyController) deleteCNP(old interface{}) {
	cnp, ok := old.(*crdv1beta1.ClusterNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ClusterNetworkPolicy, invalid type: %v", old)
			return
		}
		cnp, ok = tombstone.Obj.(*crdv1beta1.ClusterNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ClusterNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	klog.Infof("Processing ClusterNetworkPolicy %s DELETE event", cnp.Name)
}
