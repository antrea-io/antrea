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

package member

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

const (
	// cached indexer
	resImportIndexer = "name.kind"
)

func resImportIndexerFunc(obj interface{}) ([]string, error) {
	ri := obj.(multiclusterv1alpha1.ResourceImport)
	return []string{ri.Spec.Namespace + "/" + ri.Spec.Name + "/" + ri.Spec.Kind}, nil
}

func resImportIndexerKeyFunc(obj interface{}) (string, error) {
	ri := obj.(multiclusterv1alpha1.ResourceImport)
	return common.NamespacedName(ri.Namespace, ri.Name), nil
}

// ResourceImportReconciler reconciles a ResourceImport object in the member cluster.
type ResourceImportReconciler struct {
	localClusterClient  client.Client
	localClusterID      string
	namespace           string
	remoteCommonArea    commonarea.RemoteCommonArea
	installedResImports cache.Indexer
	// Saved Manager to indicate SetupWithManager() is done or not.
	manager ctrl.Manager
}

func newResourceImportReconciler(localClusterClient client.Client,
	localClusterID string, namespace string, remoteCommonArea commonarea.RemoteCommonArea) *ResourceImportReconciler {
	return &ResourceImportReconciler{
		localClusterClient: localClusterClient,
		localClusterID:     localClusterID,
		namespace:          namespace,
		remoteCommonArea:   remoteCommonArea,
		installedResImports: cache.NewIndexer(resImportIndexerKeyFunc, cache.Indexers{
			resImportIndexer: resImportIndexerFunc,
		}),
	}
}

// +kubebuilder:rbac:groups=crd.antrea.io,resources=clusternetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=crd.antrea.io,resources=tiers,verbs=get;list;watch
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports/finalizers,verbs=update
// +kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceimports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceimports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch;update;create;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;create;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create

// Reconcile will attempt to ensure that the imported Resource is installed in local cluster as per the
// ResourceImport object.
func (r *ResourceImportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling ResourceImport", "resourceimport", req.NamespacedName)
	// TODO: Must check whether this ResourceImport must be reconciled by this member cluster. Check `spec.clusters` field.
	var resImp multiclusterv1alpha1.ResourceImport
	err := r.remoteCommonArea.Get(ctx, req.NamespacedName, &resImp)
	var isDeleted bool
	if err != nil {
		isDeleted = apierrors.IsNotFound(err)
		if !isDeleted {
			klog.InfoS("Unable to fetch ResourceImport", "resourceimport", req.NamespacedName.String(), "err", err)
			return ctrl.Result{}, err
		} else {
			resImpObj, exist, err := r.installedResImports.GetByKey(req.NamespacedName.String())
			if exist {
				resImp = resImpObj.(multiclusterv1alpha1.ResourceImport)
			} else {
				// stale_controller will reconcile and clean up MC Service/ServiceImport, so it's ok to return nil here
				klog.ErrorS(err, "No cached data for ResourceImport", "resourceimport", req.NamespacedName.String())
				return ctrl.Result{}, nil
			}
		}
	}
	switch resImp.Spec.Kind {
	case constants.ServiceImportKind:
		if isDeleted {
			return r.handleResImpDeleteForService(ctx, &resImp)
		}
		return r.handleResImpUpdateForService(ctx, &resImp)
	case constants.EndpointsKind:
		if isDeleted {
			return r.handleResImpDeleteForEndpoints(ctx, &resImp)
		}
		return r.handleResImpUpdateForEndpoints(ctx, &resImp)
	case constants.AntreaClusterNetworkPolicyKind:
		if isDeleted {
			return r.handleResImpDeleteForClusterNetworkPolicy(ctx, &resImp)
		}
		return r.handleResImpUpdateForClusterNetworkPolicy(ctx, &resImp)
	case constants.ClusterInfoKind:
		if isDeleted {
			return r.handleResImpDeleteForClusterInfo(ctx, req, &resImp)
		}
		return r.handleResImpUpdateForClusterInfo(ctx, req, &resImp)
	}
	return ctrl.Result{}, nil
}

func (r *ResourceImportReconciler) handleResImpUpdateForService(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	svcImpName := types.NamespacedName{Namespace: resImp.Spec.Namespace, Name: resImp.Spec.Name}
	svcName := types.NamespacedName{Namespace: resImp.Spec.Namespace, Name: common.ToMCResourceName(resImp.Spec.Name)}
	klog.InfoS("Updating Service and ServiceImport corresponding to ResourceImport",
		"service", svcName.String(), "serviceimport", svcImpName.String(), "resourceimport", klog.KObj(resImp))

	svc := &corev1.Service{}
	err := r.localClusterClient.Get(ctx, svcName, svc)
	svcNotFound := apierrors.IsNotFound(err)
	if err != nil && !svcNotFound {
		return ctrl.Result{}, err
	}
	if !svcNotFound {
		// Here we will skip creating derived MC Service when a Service with the same name
		// already exists but it's not previously created by Importer.
		if _, ok := svc.Annotations[common.AntreaMCServiceAnnotation]; !ok {
			err := errors.New("the Service conflicts with existing one")
			klog.ErrorS(err, "Unable to import Service", "service", klog.KObj(svc))
			return ctrl.Result{}, err
		}
	}
	svcObj := getMCService(resImp)
	if svcNotFound {
		err := r.localClusterClient.Create(ctx, svcObj, &client.CreateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to create Service", "service", klog.KObj(svcObj))
			return ctrl.Result{}, err
		}
		if err = r.localClusterClient.Get(ctx, svcName, svc); err != nil {
			// Ignore the error here, and requeue the event again when both Service
			// and ServiceImport are created later
			klog.ErrorS(err, "Failed to get latest imported Service", "service", klog.KObj(svcObj))
		}
	}

	svcImp := &k8smcsv1alpha1.ServiceImport{}
	err = r.localClusterClient.Get(ctx, svcImpName, svcImp)
	svcImpNotFound := apierrors.IsNotFound(err)
	if err != nil && !svcImpNotFound {
		return ctrl.Result{}, err
	}
	svcImpObj := getMCServiceImport(resImp)
	// Set multi-cluster Service's ClusterIP as ServiceImport's ClusterSetIP
	if svc.Spec.ClusterIP != "" {
		svcImpObj.Spec.IPs = []string{svc.Spec.ClusterIP}
	}
	if svcImpNotFound {
		err := r.localClusterClient.Create(ctx, svcImpObj, &client.CreateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to create ServiceImport", "serviceimport", klog.KObj(svcImpObj))
			return ctrl.Result{}, err
		}
		r.installedResImports.Add(*resImp)
		if len(svcImpObj.Spec.IPs) == 0 {
			// Requeue the event to update ServiceImport's ClusterSetIP
			return ctrl.Result{}, fmt.Errorf("ServiceImport %s ClusterSetIP is empty", klog.KObj(svcImpObj))
		}
		return ctrl.Result{}, nil
	}

	// TODO: check label difference ?
	if !apiequality.Semantic.DeepEqual(svc.Spec.Ports, svcObj.Spec.Ports) {
		svc.Spec.Ports = svcObj.Spec.Ports
		err = r.localClusterClient.Update(ctx, svc, &client.UpdateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to update imported Service", "service", svcName.String())
			return ctrl.Result{}, err
		}
	}

	if !apiequality.Semantic.DeepEqual(svcImp.Spec, svcImpObj.Spec) {
		svcImp.Spec = svcImpObj.Spec
		err = r.localClusterClient.Update(ctx, svcImp, &client.UpdateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to update ServiceImport", "serviceimport", svcImpName.String())
			return ctrl.Result{}, err
		}
	}
	r.installedResImports.Update(*resImp)
	return ctrl.Result{}, nil
}

func (r *ResourceImportReconciler) handleResImpDeleteForService(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	svcImpName := common.NamespacedName(resImp.Spec.Namespace, resImp.Spec.Name)
	svcName := common.NamespacedName(resImp.Spec.Namespace, common.ToMCResourceName(resImp.Spec.Name))
	klog.InfoS("Deleting Service and ServiceImport corresponding to ResourceImport", "service", svcName,
		"serviceImport", svcImpName, "resourceimport", klog.KObj(resImp))

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: resImp.Spec.Namespace,
			Name:      common.ToMCResourceName(resImp.Spec.Name),
		},
	}
	err := r.localClusterClient.Delete(ctx, svc, &client.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete imported Service", "service", svcName)
		return ctrl.Result{}, err
	}

	svcImp := &k8smcsv1alpha1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: resImp.Spec.Namespace,
			Name:      resImp.Spec.Name,
		},
	}
	err = client.IgnoreNotFound(r.localClusterClient.Delete(ctx, svcImp, &client.DeleteOptions{}))
	if err != nil {
		klog.ErrorS(err, "Failed to delete ServiceImport for ResourceImport", "serviceImport", svcImpName)
		return ctrl.Result{}, err
	}
	r.installedResImports.Delete(*resImp)
	return ctrl.Result{}, nil
}

func (r *ResourceImportReconciler) handleResImpUpdateForEndpoints(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	epName := common.ToMCResourceName(resImp.Spec.Name)
	epNamespaced := types.NamespacedName{Namespace: resImp.Spec.Namespace, Name: epName}
	klog.InfoS("Updating Endpoints corresponding to ResourceImport", "endpoints", epNamespaced.String(),
		"resourceimport", klog.KObj(resImp))

	ep := &corev1.Endpoints{}
	err := r.localClusterClient.Get(ctx, epNamespaced, ep)
	epNotFound := apierrors.IsNotFound(err)
	if err != nil && !epNotFound {
		return ctrl.Result{}, err
	}
	if !epNotFound {
		if _, ok := ep.Annotations[common.AntreaMCServiceAnnotation]; !ok {
			err := errors.New("the Endpoints conflicts with existing one")
			klog.ErrorS(err, "Unable to import Endpoints", "endpoints", klog.KObj(ep))
			return ctrl.Result{}, err
		}
	}

	newSubsets := resImp.Spec.Endpoints.Subsets
	mcsEpObj := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:        epName,
			Namespace:   resImp.Spec.Namespace,
			Annotations: map[string]string{common.AntreaMCServiceAnnotation: "true"},
		},
		Subsets: newSubsets,
	}
	if epNotFound {
		err := r.localClusterClient.Create(ctx, mcsEpObj, &client.CreateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to create MCS Endpoints", "endpoints", klog.KObj(mcsEpObj), err)
			return ctrl.Result{}, err
		}
		r.installedResImports.Add(*resImp)
		return ctrl.Result{}, nil
	}
	if _, ok := ep.Annotations[common.AntreaMCServiceAnnotation]; !ok {
		klog.InfoS("Endpoints has no desired annotation, skip update", "annotation", common.AntreaMCServiceAnnotation, "endpoints", epNamespaced.String())
		return ctrl.Result{}, nil
	}
	// TODO: check label difference ?
	if !apiequality.Semantic.DeepEqual(newSubsets, ep.Subsets) {
		ep.Subsets = newSubsets
		err = r.localClusterClient.Update(ctx, ep, &client.UpdateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to update MCS Endpoints", "endpoints", epNamespaced.String())
			return ctrl.Result{}, err
		}
	}
	r.installedResImports.Update(*resImp)
	return ctrl.Result{}, nil
}

func (r *ResourceImportReconciler) handleResImpDeleteForEndpoints(ctx context.Context, resImp *multiclusterv1alpha1.ResourceImport) (ctrl.Result, error) {
	epName := common.ToMCResourceName(resImp.Spec.Name)
	epNamespacedName := common.NamespacedName(resImp.Spec.Namespace, epName)
	klog.InfoS("Deleting Endpoints corresponding to ResourceImport", "endpoints", epNamespacedName,
		"resourceimport", klog.KObj(resImp))

	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      epName,
			Namespace: resImp.Spec.Namespace,
		},
	}
	err := client.IgnoreNotFound(r.localClusterClient.Delete(ctx, ep, &client.DeleteOptions{}))
	if err != nil {
		klog.ErrorS(err, "Failed to delete imported Endpoints", "endpoints", epNamespacedName)
		return ctrl.Result{}, err
	}
	r.installedResImports.Delete(*resImp)
	return ctrl.Result{}, nil
}

func getMCService(resImp *multiclusterv1alpha1.ResourceImport) *corev1.Service {
	var mcsPorts []corev1.ServicePort
	for _, p := range resImp.Spec.ServiceImport.Spec.Ports {
		mcsPorts = append(mcsPorts, corev1.ServicePort{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: p.Protocol,
		})
	}
	mcs := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.ToMCResourceName(resImp.Spec.Name),
			Namespace: resImp.Spec.Namespace,
			Annotations: map[string]string{
				common.AntreaMCServiceAnnotation: "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: mcsPorts,
		},
	}
	return mcs
}

func getMCServiceImport(resImp *multiclusterv1alpha1.ResourceImport) *k8smcsv1alpha1.ServiceImport {
	svcImp := &k8smcsv1alpha1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resImp.Spec.Name,
			Namespace: resImp.Spec.Namespace,
		},
		Spec: resImp.Spec.ServiceImport.Spec,
	}
	return svcImp
}

// SetupWithManager sets up the controller with the ClusterManager
// which will set up controllers for resources that need to be monitored
// in the remoteCommonArea.
func (r *ResourceImportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.manager == mgr {
		// SetupWithManager was called by a previous RemoteManager.StartWatch() call and already
		// completed with no error.
		return nil
	}

	// Ignore status update event via GenerationChangedPredicate
	generationPredicate := predicate.GenerationChangedPredicate{}
	// Register this filter to ignore LabelIdentity kind of ResourceImport
	labelIdentityResImportFilter := func(object client.Object) bool {
		if resImport, ok := object.(*multiclusterv1alpha1.ResourceImport); ok {
			return resImport.Spec.Kind != constants.LabelIdentityKind
		}
		return false
	}
	labelIdentityResImportPredicate := predicate.NewPredicateFuncs(labelIdentityResImportFilter)
	instance := predicate.And(generationPredicate, labelIdentityResImportPredicate)
	err := ctrl.NewControllerManagedBy(mgr).
		For(&multiclusterv1alpha1.ResourceImport{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)

	if err == nil {
		r.manager = mgr
	}
	return err
}
