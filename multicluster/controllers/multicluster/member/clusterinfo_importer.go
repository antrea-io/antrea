/*
Copyright 2022 Antrea Authors.

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

package member

import (
	"context"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

func (r *ResourceImportReconciler) handleResImpUpdateForClusterInfo(ctx context.Context, req ctrl.Request, resImp *mcsv1alpha1.ResourceImport) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling ClusterInfo of ResourceImport", "resourceimport", req.NamespacedName)
	var err error
	if resImp.Spec.ClusterInfo == nil {
		klog.V(2).InfoS("Skip reconciling ResourceImport for ClusterInfo since it has no valid spec", "resourceimport", req.NamespacedName)
		return ctrl.Result{}, nil
	}
	clusterInfo := *resImp.Spec.ClusterInfo

	// If ClusterInfo is from local cluster, skip it.
	if clusterInfo.ClusterID == r.localClusterID {
		klog.V(2).InfoS("Skip reconciling ResourceImport for ClusterInfo since it's from local cluster", "resourceimport", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Create or update ClusterInfoImport
	clusterInfoImport, clusterInfoImportName := newClusterInfoImport(req.Name, r.namespace)
	if err = r.localClusterClient.Get(ctx, clusterInfoImportName, clusterInfoImport); err != nil {
		if apierrors.IsNotFound(err) {
			clusterInfoImport.Spec = clusterInfo
			if err = r.localClusterClient.Create(ctx, clusterInfoImport, &client.CreateOptions{}); err != nil {
				return ctrl.Result{}, err
			}
			r.installedResImports.Add(*resImp)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if reflect.DeepEqual(clusterInfoImport.Spec, clusterInfo) {
		klog.InfoS("No change on ClusterInfoImport spec, skip reconciling", "clusterinfoimport", clusterInfoImportName.String(),
			"resourceimport", req.NamespacedName.String())
		r.installedResImports.Update(*resImp)
		return ctrl.Result{}, nil
	}
	clusterInfoImport.Spec = clusterInfo
	if err = r.localClusterClient.Update(ctx, clusterInfoImport, &client.UpdateOptions{}); err != nil {
		return ctrl.Result{}, err
	}
	r.installedResImports.Update(*resImp)
	return ctrl.Result{}, nil
}

func (r *ResourceImportReconciler) handleResImpDeleteForClusterInfo(ctx context.Context, req ctrl.Request, resImp *mcsv1alpha1.ResourceImport) (ctrl.Result, error) {
	clusterInfoImport, clusterInfoImportName := newClusterInfoImport(req.Name, r.namespace)
	klog.InfoS("Deleting ClusterInfoImport", "clusterinfoimport", clusterInfoImportName.String())
	err := client.IgnoreNotFound(r.localClusterClient.Delete(ctx, clusterInfoImport, &client.DeleteOptions{}))
	if err != nil {
		klog.ErrorS(err, "Failed to delete imported ClusterInfo", "clusterInfo", clusterInfoImportName)
		return ctrl.Result{}, err
	}
	r.installedResImports.Delete(*resImp)
	return ctrl.Result{}, nil
}

func newClusterInfoImport(name, namespace string) (*mcsv1alpha1.ClusterInfoImport, types.NamespacedName) {
	clusterInfoImport := &mcsv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	clusterInfoImportName := types.NamespacedName{Name: name, Namespace: namespace}
	return clusterInfoImport, clusterInfoImportName
}
