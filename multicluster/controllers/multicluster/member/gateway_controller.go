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

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

type (
	// GatewayReconciler is for member cluster only.
	GatewayReconciler struct {
		client.Client
		Scheme           *runtime.Scheme
		commonAreaGetter commonarea.RemoteCommonAreaGetter
		namespace        string
		localClusterID   string
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
	podCIDRs []string,
	commonAreaGetter commonarea.RemoteCommonAreaGetter) *GatewayReconciler {
	reconciler := &GatewayReconciler{
		Client:           client,
		Scheme:           scheme,
		namespace:        namespace,
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
	var commonArea commonarea.RemoteCommonArea
	// TODO: there is a possibility that the ClusterSet is to be deleted after getting the commonArea,
	// then there might be new ResourceExports created in the leader after the member cluster
	// is removed from the ClusterSet. We need to handle such corner cases in the future release.
	commonArea, r.localClusterID, _ = r.commonAreaGetter.GetRemoteCommonAreaAndLocalID()
	if commonArea == nil {
		klog.V(2).InfoS("Skip reconciling Gateway since there is no connection to the leader")
		return ctrl.Result{}, nil
	}
	r.leaderNamespace = commonArea.GetNamespace()

	resExportName := common.NewClusterInfoResourceExportName(r.localClusterID)
	resExportNamespacedName := types.NamespacedName{
		Name:      resExportName,
		Namespace: r.leaderNamespace,
	}
	resExport := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resExportName,
			Namespace: r.leaderNamespace,
		},
	}

	createOrUpdate := func(gateway *mcv1alpha1.Gateway) error {
		existingResExport := &mcv1alpha1.ResourceExport{}
		err := commonArea.Get(ctx, resExportNamespacedName, existingResExport)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if apierrors.IsNotFound(err) || !existingResExport.DeletionTimestamp.IsZero() {
			if err = r.createResourceExport(ctx, req, commonArea, gateway); err != nil {
				return err
			}
			return nil
		}
		// updateResourceExport will update latest Gateway information with the existing ResourceExport's resourceVersion.
		// It will return an error and retry when there is a version conflict.
		if err = r.updateResourceExport(ctx, req, commonArea, existingResExport, gateway); err != nil {
			return err
		}
		return nil
	}

	gw := &mcv1alpha1.Gateway{}
	if err := r.Client.Get(ctx, req.NamespacedName, gw); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if err := commonArea.Delete(ctx, resExport, &client.DeleteOptions{}); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, nil
	}

	if err := createOrUpdate(gw); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) updateResourceExport(ctx context.Context, req ctrl.Request,
	commonArea commonarea.RemoteCommonArea, existingResExport *mcv1alpha1.ResourceExport, gw *mcv1alpha1.Gateway) error {
	resExportSpec := mcv1alpha1.ResourceExportSpec{
		Kind:      constants.ClusterInfoKind,
		ClusterID: r.localClusterID,
		Name:      r.localClusterID,
		Namespace: r.namespace,
	}
	resExportSpec.ClusterInfo = r.getClusterInfo(gw)
	klog.V(2).InfoS("Updating ClusterInfo kind of ResourceExport", "clusterinfo", klog.KObj(existingResExport),
		"gateway", req.NamespacedName)
	existingResExport.Spec = resExportSpec
	if err := commonArea.Update(ctx, existingResExport, &client.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}

func (r *GatewayReconciler) createResourceExport(ctx context.Context, req ctrl.Request,
	commonArea commonarea.RemoteCommonArea, gateway *mcv1alpha1.Gateway) error {
	resExportSpec := mcv1alpha1.ResourceExportSpec{
		Kind:      constants.ClusterInfoKind,
		ClusterID: r.localClusterID,
		Name:      r.localClusterID,
		Namespace: r.namespace,
	}
	resExportSpec.ClusterInfo = r.getClusterInfo(gateway)
	resExport := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.leaderNamespace,
			Name:      common.NewClusterInfoResourceExportName(r.localClusterID),
		},
		Spec: resExportSpec,
	}
	resExport.Finalizers = []string{constants.ResourceExportFinalizer}
	if err := commonArea.Create(ctx, resExport, &client.CreateOptions{}); err != nil {
		return err
	}
	klog.InfoS("Created a ClusterInfo kind of ResourceExport", "clusterinfo", klog.KObj(resExport))
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcv1alpha1.Gateway{}).
		Watches(&mcv1alpha2.ClusterSet{}, handler.EnqueueRequestsFromMapFunc(r.clusterSetMapFunc),
			builder.WithPredicates(statusReadyPredicate)).
		WithOptions(controller.Options{
			// TODO: add a lock for r.serviceCIDR and r.localClusterID if
			//  there is any plan to increase this concurrent number.
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

func (r *GatewayReconciler) clusterSetMapFunc(ctx context.Context, a client.Object) []reconcile.Request {
	clusterSet := &mcv1alpha2.ClusterSet{}
	requests := []reconcile.Request{}
	if a.GetNamespace() != r.namespace {
		return requests
	}
	err := r.Client.Get(ctx, types.NamespacedName{Namespace: a.GetNamespace(), Name: a.GetName()}, clusterSet)
	if err == nil {
		if len(clusterSet.Status.Conditions) > 0 && clusterSet.Status.Conditions[0].Status == v1.ConditionTrue {
			gwList := &mcv1alpha1.GatewayList{}
			r.Client.List(ctx, gwList, &client.ListOptions{Namespace: r.namespace})
			requests = make([]reconcile.Request, len(gwList.Items))
			for i, gw := range gwList.Items {
				requests[i] = reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: gw.Namespace,
						Name:      gw.Name,
					},
				}
			}
		}
	}
	return requests
}

func (r *GatewayReconciler) getClusterInfo(gateway *mcv1alpha1.Gateway) *mcv1alpha1.ClusterInfo {
	clusterInfo := &mcv1alpha1.ClusterInfo{
		ClusterID:   r.localClusterID,
		ServiceCIDR: gateway.ServiceCIDR,
		PodCIDRs:    r.podCIDRs,
		GatewayInfos: []mcv1alpha1.GatewayInfo{
			{
				GatewayIP: gateway.GatewayIP,
			},
		},
	}
	if gateway.WireGuard != nil && gateway.WireGuard.PublicKey != "" {
		clusterInfo.WireGuard = &mcv1alpha1.WireGuardInfo{
			PublicKey: gateway.WireGuard.PublicKey,
		}
	}

	return clusterInfo
}
