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
	"context"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

type (
	svcInfo struct {
		name       string
		namespace  string
		clusterIPs []string
		ports      []corev1.ServicePort
		svcType    string
	}

	epInfo struct {
		name      string
		namespace string
		subsets   []corev1.EndpointSubset
	}

	// ServiceExportReconciler reconciles a ServiceExport object in the member cluster.
	ServiceExportReconciler struct {
		client.Client
		mutex            sync.Mutex
		Scheme           *runtime.Scheme
		commonAreaGetter RemoteCommonAreaGetter
		remoteCommonArea commonarea.RemoteCommonArea
		installedSvcs    cache.Indexer
		installedEps     cache.Indexer
		leaderNamespace  string
		leaderClusterID  string
		localClusterID   string
		endpointIPType   string
	}
)

type reason int

const (
	serviceNotFound reason = iota
	isImportedService
	serviceWithoutEndpoints
	serviceExported
)

func NewServiceExportReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	commonAreaGetter RemoteCommonAreaGetter,
	endpointIPType string) *ServiceExportReconciler {
	reconciler := &ServiceExportReconciler{
		Client:           client,
		Scheme:           scheme,
		commonAreaGetter: commonAreaGetter,
		endpointIPType:   endpointIPType,
		installedSvcs:    cache.NewIndexer(svcInfoKeyFunc, cache.Indexers{}),
		installedEps:     cache.NewIndexer(epInfoKeyFunc, cache.Indexers{}),
	}
	return reconciler
}

func svcInfoKeyFunc(obj interface{}) (string, error) {
	svc := obj.(*svcInfo)
	return common.NamespacedName(svc.namespace, svc.name), nil
}

func epInfoKeyFunc(obj interface{}) (string, error) {
	ep := obj.(*epInfo)
	return common.NamespacedName(ep.namespace, ep.name), nil
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/finalizers,verbs=update
//+kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceexports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceexports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For ServiceExport Reconcile, it watches events of ServiceExport resources,
// and also Services/Endpoints resources. It will create/update/remove ResourceExport
// in a leader cluster for corresponding ServiceExport from a member cluster.
func (r *ServiceExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling ServiceExport", "serviceexport", req.NamespacedName)
	svcExportList := &k8smcsv1alpha1.ServiceExportList{}
	err := r.Client.List(ctx, svcExportList, &client.ListOptions{})
	if err != nil {
		return ctrl.Result{}, err
	}

	// Return faster during initialization instead of handling all Service/Endpoints events
	if len(svcExportList.Items) == 0 && len(r.installedSvcs.List()) == 0 {
		klog.InfoS("Skip reconciling, no corresponding ServiceExport")
		return ctrl.Result{}, nil
	}
	if requeue := r.checkRemoteCommonArea(); requeue {
		return ctrl.Result{Requeue: true}, nil
	}
	var svcExport k8smcsv1alpha1.ServiceExport
	svcObj, svcInstalled, _ := r.installedSvcs.GetByKey(req.String())
	epsObj, epsInstalled, _ := r.installedEps.GetByKey(req.String())
	svcResExportName := getResourceExportName(r.localClusterID, req, "service")
	epResExportName := getResourceExportName(r.localClusterID, req, "endpoints")

	cleanup := func() error {
		// When controller restarts, the Service is not in cache, but it is still possible
		// we need to remove ResourceExports. So leave it to the caller to check the 'svcInstalled'
		// before deletion or try to delete any way.
		err = r.handleServiceDeleteEvent(ctx, req, r.remoteCommonArea)
		if err != nil {
			return err
		}
		err = r.handleEndpointDeleteEvent(ctx, req, r.remoteCommonArea)
		if err != nil {
			return err
		}
		if svcInstalled {
			r.installedSvcs.Delete(svcObj)
		}
		if epsInstalled {
			r.installedEps.Delete(epsObj)
		}
		return nil
	}

	if err := r.Client.Get(ctx, req.NamespacedName, &svcExport); err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Unable to fetch ServiceExport", "serviceexport", req.String())
			return ctrl.Result{}, err
		}
		// Stale resources will be cleaned up by stale controller if controller restart,
		// so here we check if Service is installed or not to avoid unnecessary deletion.
		if svcInstalled {
			if err := cleanup(); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// If the corresponding Service doesn't exist, update ServiceExport's status reason to
	// 'service_not_found', and clean up remote ResourceExport.
	svc := &corev1.Service{}
	err = r.Client.Get(ctx, req.NamespacedName, svc)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if err := cleanup(); err != nil {
				return ctrl.Result{}, err
			}
			err = r.updateSvcExportStatus(ctx, req, serviceNotFound)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		klog.ErrorS(err, "Failed to get Service", req.String())
		return ctrl.Result{}, err
	}

	// Skip if ServiceExport is trying to export a multi-cluster Service.
	if !svcInstalled {
		if _, ok := svc.Annotations[common.AntreaMCServiceAnnotation]; ok {
			klog.InfoS("It's not allowed to export the multi-cluster controller auto-generated Service", "service", req.String())
			err = r.updateSvcExportStatus(ctx, req, isImportedService)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	}

	// Delete existing ResourceExport if the exported Service has no ready Endpoints,
	// and update the ServiceExport status.
	eps := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}
	readyAddresses := 0
	err = r.Client.Get(ctx, req.NamespacedName, eps)
	if err == nil {
		for _, subsets := range eps.Subsets {
			readyAddresses = readyAddresses + len(subsets.Addresses)
		}
	} else {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get Endpoints", req.String())
			return ctrl.Result{}, err
		}
	}
	if readyAddresses == 0 || apierrors.IsNotFound(err) {
		if err := cleanup(); err != nil {
			return ctrl.Result{}, err
		}
		err = r.updateSvcExportStatus(ctx, req, serviceWithoutEndpoints)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// We also watch Service events via events mapping function.
	// Need to check cache and compare with cache if there is any change for Service.
	var svcNoChange, epNoChange bool
	svcExportNSName := common.NamespacedName(r.leaderNamespace, svcResExportName)
	epExportNSName := common.NamespacedName(r.leaderNamespace, epResExportName)
	if svcInstalled {
		installedSvc := svcObj.(*svcInfo)
		if apiequality.Semantic.DeepEqual(svc.Spec.Ports, installedSvc.ports) &&
			apiequality.Semantic.DeepEqual(svc.Spec.ClusterIPs, installedSvc.clusterIPs) {
			klog.InfoS("Service has been converted into ResourceExport and no change, skip it", "service",
				req.String(), "resourceexport", svcExportNSName)
			svcNoChange = true
		}
	}

	if r.endpointIPType == "ClusterIP" {
		eps.Subsets = []corev1.EndpointSubset{common.GetServiceEndpointSubset(svc)}
	} else {
		newSubsets := common.FilterEndpointSubsets(eps.Subsets)
		if epsInstalled {
			installedEp := epsObj.(*epInfo)
			if apiequality.Semantic.DeepEqual(newSubsets, installedEp.subsets) {
				klog.InfoS("Endpoints has been converted into ResourceExport and no change, skip it", "endpoints",
					req.String(), "resourceexport", epExportNSName)
				epNoChange = true
			}
		}
		if !epNoChange {
			eps.Subsets = newSubsets
		}
	}

	if svcNoChange && epNoChange {
		return ctrl.Result{}, nil
	}

	re := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.leaderNamespace,
			Labels: map[string]string{
				common.SourceName:      req.Name,
				common.SourceNamespace: req.Namespace,
				common.SourceClusterID: r.localClusterID,
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: r.localClusterID,
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}

	if !svcNoChange {
		klog.InfoS("Service has new changes, update ResourceExport", "service", req.String(),
			"resourceexport", svcExportNSName)
		err := r.serviceHandler(ctx, req, svc, svcResExportName, re, r.remoteCommonArea)
		if err != nil {
			klog.ErrorS(err, "Failed to handle Service change", "service", req.String())
			return ctrl.Result{}, err
		}

		err = r.updateSvcExportStatus(ctx, req, serviceExported)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	if !epNoChange {
		klog.InfoS("Endpoints have new change, update ResourceExport", "endpoints",
			req.String(), "resourceexport", epExportNSName)
		err = r.endpointsHandler(ctx, req, eps, epResExportName, re, r.remoteCommonArea)
		if err != nil {
			klog.ErrorS(err, "Failed to handle Endpoints change", "endpoints", req.String())
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// checkRemoteCommonArea initializes remoteCommonArea for the reconciler if necessary,
// or tells the Reconcile function to requeue if the remoteCommonArea is not ready.
func (r *ServiceExportReconciler) checkRemoteCommonArea() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.remoteCommonArea == nil {
		commonArea, localClusterID, _ := r.commonAreaGetter.GetRemoteCommonAreaAndLocalID()
		if commonArea == nil {
			return true
		}
		r.leaderClusterID, r.localClusterID = string(commonArea.GetClusterID()), localClusterID
		r.leaderNamespace = commonArea.GetNamespace()
		r.remoteCommonArea = commonArea
	}
	return false
}

func (r *ServiceExportReconciler) handleServiceDeleteEvent(ctx context.Context, req ctrl.Request,
	commonArea commonarea.RemoteCommonArea) error {
	svcResExportName := getResourceExportName(r.localClusterID, req, "service")
	svcResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcResExportName,
			Namespace: r.leaderNamespace,
		},
	}

	// clean up Service kind of ResourceExport in remote leader cluster
	svcResExportNamespacedName := common.NamespacedName(r.leaderNamespace, svcResExportName)
	err := commonArea.Delete(ctx, svcResExport, &client.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete ResourceExport in remote cluster", "resourceexport",
			svcResExportNamespacedName, "clusterID", r.leaderClusterID)
		return err
	}
	klog.V(2).InfoS("Clean up ResourceExport in remote cluster", "resourceexport", svcResExportNamespacedName)
	return nil
}

func (r *ServiceExportReconciler) handleEndpointDeleteEvent(ctx context.Context, req ctrl.Request,
	commonArea commonarea.RemoteCommonArea) error {
	epResExportName := getResourceExportName(r.localClusterID, req, "endpoints")
	epResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      epResExportName,
			Namespace: r.leaderNamespace,
		},
	}

	// clean up Endpoints kind of ResourceExport in remote leader cluster
	epResExportNamespacedName := common.NamespacedName(r.leaderNamespace, epResExportName)
	err := commonArea.Delete(ctx, epResExport, &client.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete ResourceExport in remote cluster", "resourceexport",
			epResExportNamespacedName, "clusterID", r.leaderClusterID)
		return err
	}

	klog.V(2).InfoS("Clean up ResourceExport in remote cluster", "resourceexport", epResExportNamespacedName)
	return nil
}

func (r *ServiceExportReconciler) updateSvcExportStatus(ctx context.Context, req ctrl.Request, cause reason) error {
	svcExport := &k8smcsv1alpha1.ServiceExport{}
	err := r.Client.Get(ctx, req.NamespacedName, svcExport)
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	now := metav1.Now()
	newCondition := k8smcsv1alpha1.ServiceExportCondition{
		Type:               k8smcsv1alpha1.ServiceExportValid,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: &now,
	}

	switch cause {
	case serviceNotFound:
		newCondition.Reason = getStringPointer("service_not_found")
		newCondition.Message = getStringPointer("the Service does not exist")
	case serviceWithoutEndpoints:
		newCondition.Reason = getStringPointer("service_without_endpoints")
		newCondition.Message = getStringPointer("the Service has no Endpoints, failed to export")
	case isImportedService:
		newCondition.Reason = getStringPointer("imported_service")
		newCondition.Message = getStringPointer("the Service is imported, not allowed to export")
	case serviceExported:
		newCondition.Status = corev1.ConditionTrue
		newCondition.Reason = getStringPointer("export_succeeded")
		newCondition.Message = getStringPointer("the Service is exported successfully")
	}

	svcExportConditions := svcExport.Status.DeepCopy().Conditions
	var existingCondition k8smcsv1alpha1.ServiceExportCondition
	matchedConditionIdx := 0
	for n, c := range svcExportConditions {
		if c.Type == k8smcsv1alpha1.ServiceExportValid {
			existingCondition = c
			matchedConditionIdx = n
			break
		}
	}

	if existingCondition != (k8smcsv1alpha1.ServiceExportCondition{}) {
		if *existingCondition.Reason == *newCondition.Reason {
			// No need to update the ServiceExport when there is no status change.
			return nil
		}
	}

	if existingCondition != (k8smcsv1alpha1.ServiceExportCondition{}) {
		svcExportConditions[matchedConditionIdx] = newCondition
	} else {
		svcExportConditions = append(svcExportConditions, newCondition)
	}

	svcExport.Status = k8smcsv1alpha1.ServiceExportStatus{
		Conditions: svcExportConditions,
	}
	err = r.Client.Status().Update(ctx, svcExport)
	if err != nil {
		klog.ErrorS(err, "Failed to update ServiceExport", "serviceexport", req.String())
		return client.IgnoreNotFound(err)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceExportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Watch events only when resource version changes
	versionChange := predicate.ResourceVersionChangedPredicate{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&k8smcsv1alpha1.ServiceExport{}).
		Watches(&source.Kind{Type: &corev1.Service{}}, handler.EnqueueRequestsFromMapFunc(objectMapFunc)).
		Watches(&source.Kind{Type: &corev1.Endpoints{}}, handler.EnqueueRequestsFromMapFunc(objectMapFunc)).
		WithEventFilter(versionChange).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

// objectMapFunc simply maps all Serivce and Endpoints events to ServiceExports.
// When there are any Service or Endpoints changes, it might be reflected in ResourceExport
// in leader cluster as well, so ServiceExportReconciler also needs to watch
// Service and Endpoints events.
func objectMapFunc(a client.Object) []reconcile.Request {
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      a.GetName(),
				Namespace: a.GetNamespace(),
			},
		},
	}
}

// serviceHandler handles Service related change.
// ClusterIP type: update corresponding ResourceExport only when ClusterIP or Ports change.
func (r *ServiceExportReconciler) serviceHandler(
	ctx context.Context,
	req ctrl.Request,
	svc *corev1.Service,
	resName string,
	re mcsv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	kind := common.ServiceKind
	sinfo := &svcInfo{
		name:       svc.Name,
		namespace:  svc.Namespace,
		clusterIPs: svc.Spec.ClusterIPs,
		ports:      svc.Spec.Ports,
		svcType:    string(svc.Spec.Type),
	}
	r.refreshResourceExport(resName, kind, svc, nil, &re)
	existingResExport := &mcsv1alpha1.ResourceExport{}
	resNamespaced := types.NamespacedName{Namespace: rc.GetNamespace(), Name: resName}
	err := rc.Get(ctx, resNamespaced, existingResExport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get ResourceExport", "resourceexport", resNamespaced.String())
			return err
		}
	}
	if err = r.updateOrCreateResourceExport(resName, ctx, req, &re, existingResExport, rc); err != nil {
		return err
	}
	r.installedSvcs.Add(sinfo)
	return nil
}

// endpointsHandler handles Endpoints related change.
// - update corresponding ResourceExport only when Ports or Addresses IP change.
func (r *ServiceExportReconciler) endpointsHandler(
	ctx context.Context,
	req ctrl.Request,
	eps *corev1.Endpoints,
	resName string,
	re mcsv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	kind := common.EndpointsKind
	epInfo := &epInfo{
		name:      eps.Name,
		namespace: eps.Namespace,
		subsets:   eps.Subsets,
	}
	r.refreshResourceExport(resName, kind, nil, eps, &re)
	existingResExport := &mcsv1alpha1.ResourceExport{}
	resNamespaced := types.NamespacedName{Namespace: rc.GetNamespace(), Name: resName}
	err := rc.Get(ctx, resNamespaced, existingResExport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get ResourceExport", "resourceexport", resNamespaced.String())
			return err
		}
	}
	if err = r.updateOrCreateResourceExport(resName, ctx, req, &re, existingResExport, rc); err != nil {
		return err
	}
	r.installedEps.Add(epInfo)
	return nil
}

func (r *ServiceExportReconciler) refreshResourceExport(resName, kind string,
	svc *corev1.Service,
	ep *corev1.Endpoints,
	re *mcsv1alpha1.ResourceExport) mcsv1alpha1.ResourceExport {
	re.Spec.Kind = kind
	switch kind {
	case common.ServiceKind:
		re.ObjectMeta.Name = resName
		re.Spec.Service = &mcsv1alpha1.ServiceExport{
			ServiceSpec: svc.Spec,
		}
		re.Labels[common.SourceKind] = common.ServiceKind
	case common.EndpointsKind:
		re.ObjectMeta.Name = resName
		re.Spec.Endpoints = &mcsv1alpha1.EndpointsExport{
			Subsets: ep.Subsets,
		}
		re.Labels[common.SourceKind] = common.EndpointsKind
	}
	return *re
}

func (r *ServiceExportReconciler) updateOrCreateResourceExport(resName string,
	ctx context.Context,
	req ctrl.Request,
	newResExport *mcsv1alpha1.ResourceExport,
	existingResExport *mcsv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	createResExport := reflect.DeepEqual(*existingResExport, mcsv1alpha1.ResourceExport{})
	resNamespaced := types.NamespacedName{Namespace: rc.GetNamespace(), Name: resName}
	if createResExport {
		// We are using Finalizers to implement asynchronous pre-delete hooks.
		// When a ServiceExport is deleted, the corresponding ResourceExport will have non-zero
		// DeletionTimestamp, so Leader controller can still get the deleted ResourceExport object,
		// then it can clean up any external resources like ResourceImport.
		// For more details about using Finalizers, please refer to https://book.kubebuilder.io/reference/using-finalizers.html.
		newResExport.Finalizers = []string{common.ResourceExportFinalizer}
		klog.InfoS("Creating ResourceExport", "resourceexport", resNamespaced.String())
		err := rc.Create(ctx, newResExport, &client.CreateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to create ResourceExport in leader cluster", "resourceexport", resNamespaced.String())
			return err
		}
	} else {
		newResExport.ObjectMeta.ResourceVersion = existingResExport.ObjectMeta.ResourceVersion
		newResExport.Finalizers = existingResExport.Finalizers
		err := rc.Update(ctx, newResExport, &client.UpdateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to update ResourceExport", "resourceexport", resNamespaced.String())
			return err
		}
	}

	return nil
}

func getResourceExportName(clusterID string, req ctrl.Request, kind string) string {
	return clusterID + "-" + req.Namespace + "-" + req.Name + "-" + kind
}

func getStringPointer(str string) *string {
	return &str
}
