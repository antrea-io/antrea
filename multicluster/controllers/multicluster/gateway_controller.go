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

package multicluster

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

type (
	// GatewayReconciler is for member cluster only.
	GatewayReconciler struct {
		client.Client
		Scheme           *runtime.Scheme
		commonAreaGetter RemoteCommonAreaGetter
		namespace        string
		localClusterID   string
		serviceCIDR      string
		podCIDRs         []string
		leaderNamespace  string
	}
)

// NewGatewayReconciler creates a GatewayReconciler which will watch Gateway events
// and create a ClusterInfo kind of ResourceExport in the leader cluster.
func NewGatewayReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	namespace string,
	serviceCIDR string,
	podCIDRs []string,
	commonAreaGetter RemoteCommonAreaGetter) *GatewayReconciler {
	reconciler := &GatewayReconciler{
		Client:           client,
		Scheme:           scheme,
		namespace:        namespace,
		serviceCIDR:      serviceCIDR,
		podCIDRs:         podCIDRs,
		commonAreaGetter: commonAreaGetter,
	}
	return reconciler
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=gateways,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=gateways/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=gateways/finalizers,verbs=update
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clusterinfoimports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clusterinfoimports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=clusterinfoimports/finalizers,verbs=update

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling Gateway", "gateway", req.NamespacedName)
	var err error
	var commonArea commonarea.RemoteCommonArea
	commonArea, r.localClusterID, err = r.commonAreaGetter.GetRemoteCommonAreaAndLocalID()
	if commonArea == nil {
		return ctrl.Result{Requeue: true}, err
	}
	r.leaderNamespace = commonArea.GetNamespace()
	err = r.getServiceCIDR(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}

	resExportName := newClusterInfoResourceExportName(r.localClusterID)
	resExportNamespacedName := types.NamespacedName{
		Name:      resExportName,
		Namespace: r.leaderNamespace,
	}
	resExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resExportName,
			Namespace: r.leaderNamespace,
		},
	}

	createOrUpdate := func(gwIP string) error {
		existingResExport := &mcsv1alpha1.ResourceExport{}
		err := commonArea.Get(ctx, resExportNamespacedName, existingResExport)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if apierrors.IsNotFound(err) || !existingResExport.DeletionTimestamp.IsZero() {
			if err = r.createResourceExport(ctx, req, commonArea, gwIP); err != nil {
				return err
			}
			return nil
		}
		// updateResourceExport will update latest Gateway information with the existing ResourceExport's resourceVersion.
		// It will return an error and retry when there is a version conflict.
		if err = r.updateResourceExport(ctx, req, commonArea, existingResExport, &mcsv1alpha1.GatewayInfo{GatewayIP: gwIP}); err != nil {
			return err
		}
		return nil
	}

	gw := &mcsv1alpha1.Gateway{}
	if err := r.Client.Get(ctx, req.NamespacedName, gw); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if err := commonArea.Delete(ctx, resExport, &client.DeleteOptions{}); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, nil
	}

	if err := createOrUpdate(gw.GatewayIP); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) updateResourceExport(ctx context.Context, req ctrl.Request,
	commonArea commonarea.RemoteCommonArea, existingResExport *mcsv1alpha1.ResourceExport, gwInfo *mcsv1alpha1.GatewayInfo) error {
	resExportSpec := mcsv1alpha1.ResourceExportSpec{
		Kind:      common.ClusterInfoKind,
		ClusterID: r.localClusterID,
		Name:      r.localClusterID,
		Namespace: r.namespace,
	}
	resExportSpec.ClusterInfo = &mcsv1alpha1.ClusterInfo{
		ClusterID:    r.localClusterID,
		ServiceCIDR:  r.serviceCIDR,
		PodCIDRs:     r.podCIDRs,
		GatewayInfos: []mcsv1alpha1.GatewayInfo{*gwInfo},
	}
	klog.V(2).InfoS("Updating ClusterInfo kind of ResourceExport", "clusterinfo", klog.KObj(existingResExport),
		"gateway", req.NamespacedName)
	existingResExport.Spec = resExportSpec
	if err := commonArea.Update(ctx, existingResExport, &client.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}

func (r *GatewayReconciler) createResourceExport(ctx context.Context, req ctrl.Request,
	commonArea commonarea.RemoteCommonArea, gatewayIP string) error {
	resExportSpec := mcsv1alpha1.ResourceExportSpec{
		Kind:      common.ClusterInfoKind,
		ClusterID: r.localClusterID,
		Name:      r.localClusterID,
		Namespace: r.namespace,
	}
	resExportSpec.ClusterInfo = &mcsv1alpha1.ClusterInfo{
		ClusterID:   r.localClusterID,
		ServiceCIDR: r.serviceCIDR,
		PodCIDRs:    r.podCIDRs,
		GatewayInfos: []mcsv1alpha1.GatewayInfo{
			{
				GatewayIP: gatewayIP,
			},
		},
	}
	resExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.leaderNamespace,
			Name:      newClusterInfoResourceExportName(r.localClusterID),
		},
		Spec: resExportSpec,
	}
	resExport.Finalizers = []string{common.ResourceExportFinalizer}
	if err := commonArea.Create(ctx, resExport, &client.CreateOptions{}); err != nil {
		return err
	}
	klog.InfoS("Created a ClusterInfo kind of ResourceExport", "clusterinfo", klog.KObj(resExport))
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcsv1alpha1.Gateway{}).
		WithOptions(controller.Options{
			// TODO: add a lock for r.serviceCIDR and r.localClusterID if
			//  there is any plan to increase this concurrent number.
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

// getServiceCIDR gets Service ClusterIP CIDR used in the member cluster.
func (r *GatewayReconciler) getServiceCIDR(ctx context.Context) error {
	if len(r.serviceCIDR) == 0 {
		serviceCIDR, err := findServiceCIDRByInvalidServiceCreation(ctx, r.Client, r.namespace)
		if err != nil {
			return fmt.Errorf("failed to find Service ClusterIP range automatically, you may set the 'serviceCIDR' config as an alternative, err: %v, ", err)
		}
		r.serviceCIDR = serviceCIDR
	}
	return nil
}

func newClusterInfoResourceExportName(clusterID string) string {
	return clusterID + "-clusterinfo"
}
