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
	"net"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
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
		endpoints []discovery.Endpoint
		ports     []discovery.EndpointPort
	}

	// ServiceExportReconciler reconciles a ServiceExport object in the member cluster.
	ServiceExportReconciler struct {
		client.Client
		mutex            sync.Mutex
		Scheme           *runtime.Scheme
		commonAreaGetter commonarea.RemoteCommonAreaGetter
		remoteCommonArea commonarea.RemoteCommonArea
		installedSvcs    cache.Indexer
		installedEps     cache.Indexer
		namespace        string
		leaderNamespace  string
		leaderClusterID  string
		localClusterID   string
		endpointIPType   string
	}
)

type reason int

const (
	serviceNotFound reason = iota
	serviceNotSupported
	serviceNoClusterIP
	isImportedService
	serviceWithoutEndpoints
	serviceExported
)

func NewServiceExportReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	commonAreaGetter commonarea.RemoteCommonAreaGetter,
	endpointIPType string,
	namespace string) *ServiceExportReconciler {
	reconciler := &ServiceExportReconciler{
		Client:           client,
		Scheme:           scheme,
		namespace:        namespace,
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
//+kubebuilder:rbac:groups="discovery.k8s.io",resources=endpointslices,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For ServiceExport Reconcile, it watches events of ServiceExport resources,
// and also Services/Endpoints resources. It will create/update/remove ResourceExport
// in a leader cluster for corresponding ServiceExport from a member cluster.
func (r *ServiceExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if requeue := r.checkRemoteCommonArea(); requeue {
		klog.V(2).InfoS("RemoteCommonArea not ready yet, requeue ServiceExport reconciliation",
			"serviceexport", req.NamespacedName)
		return ctrl.Result{Requeue: true}, nil
	}

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
		klog.ErrorS(err, "Failed to get Service", "service", req.String())
		return ctrl.Result{}, err
	}

	// The ExternalName type of Service is not supported since it has no ClusterIP
	// assigned to the Service.
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		err = r.updateSvcExportStatus(ctx, req, serviceNotSupported)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
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

	// newEpInfo holds the endpoint data that will be stored in the ResourceExport.
	// Endpoints/Ports are populated instead of Subsets since EndpointSlice is supported by default.
	var newEpInfo epInfo
	var hasReadyEndpoints bool
	var newEndpoints []discovery.Endpoint
	var newPorts []discovery.EndpointPort
	newEndpoints, newPorts, hasReadyEndpoints, err = r.getEndpointsFromEndpointSlice(ctx, req)
	if err != nil {
		return ctrl.Result{}, err
	}
	newEpInfo.endpoints = newEndpoints
	newEpInfo.ports = newPorts

	if !hasReadyEndpoints {
		// When the controller restarts, `svcInstalled` is false as the cache will be empty, but the available Endpoints of
		// a Service might have been decreased to zero during the controller restart, so we skip checking `svcInstalled`
		// and try to clean up anyway.
		if err := cleanup(); err != nil {
			return ctrl.Result{}, err
		}
		err = r.updateSvcExportStatus(ctx, req, serviceWithoutEndpoints)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if r.endpointIPType == common.EndpointIPTypeClusterIP {
		clusterIPEndpoints, clusterIPPorts := getClusterIPEndpointAndPorts(svc)
		if len(clusterIPEndpoints) == 0 {
			err = r.updateSvcExportStatus(ctx, req, serviceNoClusterIP)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		newEpInfo.endpoints = clusterIPEndpoints
		newEpInfo.ports = clusterIPPorts
		newEpInfo.subsets = nil

	}

	// We also watch Service events via events mapping function.
	// Need to check cache and compare with cache if there is any change for Service.
	var skipUpdateSvcResourceExport, skipUpdateEPResourceExport bool
	svcExportNSName := common.NamespacedName(r.leaderNamespace, svcResExportName)
	epExportNSName := common.NamespacedName(r.leaderNamespace, epResExportName)
	if svcInstalled {
		installedSvc := svcObj.(*svcInfo)
		if apiequality.Semantic.DeepEqual(svc.Spec.Ports, installedSvc.ports) {
			skipUpdateSvcResourceExport = true
			klog.V(2).InfoS("Service has been converted into ResourceExport and no change, skip it", "service",
				req.String(), "resourceexport", svcExportNSName)
		}
	}

	if epsInstalled {
		installedEp := epsObj.(*epInfo)
		if apiequality.Semantic.DeepEqual(newEpInfo.endpoints, installedEp.endpoints) &&
			apiequality.Semantic.DeepEqual(newEpInfo.ports, installedEp.ports) {
			// When the EndpointIPType is EndpointIPTypeClusterIP, skipUpdateEPResourceExport should be false only
			// when there is a ClusterIP/Port change or the recreation flag is true.
			skipUpdateEPResourceExport = true
			klog.V(2).InfoS("Service's Endpoints (PodIP or ClusterIP) has been converted into ResourceExport and no change, skip it", "Service",
				req.String(), "resourceexport", epExportNSName)
		}
	}

	if skipUpdateSvcResourceExport && skipUpdateEPResourceExport {
		return ctrl.Result{}, nil
	}

	re := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.leaderNamespace,
			Labels: map[string]string{
				constants.SourceName:      req.Name,
				constants.SourceNamespace: req.Namespace,
				constants.SourceClusterID: r.localClusterID,
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: r.localClusterID,
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}

	if !skipUpdateSvcResourceExport {
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

	if !skipUpdateEPResourceExport {
		klog.InfoS("Endpoints or EndpointSlices has new changes, update ResourceExport", "Service",
			req.String(), "resourceexport", epExportNSName)
		err = r.endpointsHandler(ctx, req, newEpInfo.endpoints, newEpInfo.ports, epResExportName, re, r.remoteCommonArea)
		if err != nil {
			klog.ErrorS(err, "Failed to handle Endpoints or EndpointSlices change", "service", req.String())
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
	svcResExport := &mcv1alpha1.ResourceExport{
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
	epResExport := &mcv1alpha1.ResourceExport{
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
		newCondition.Reason = ptr.To("ServiceNotFound")
		newCondition.Message = ptr.To("Service does not exist")
	case serviceNotSupported:
		newCondition.Reason = ptr.To("ServiceTypeNotSupported")
		newCondition.Message = ptr.To("Service of ExternalName type is not supported")
	case serviceNoClusterIP:
		newCondition.Reason = ptr.To("ServiceNoClusterIP")
		newCondition.Message = ptr.To("Service does not have a valid ClusterIP")
	case serviceWithoutEndpoints:
		newCondition.Reason = ptr.To("ServiceWithoutEndpoints")
		newCondition.Message = ptr.To("Service has no Endpoints")
	case isImportedService:
		newCondition.Reason = ptr.To("ImportedService")
		newCondition.Message = ptr.To("The Service is imported, not allowed to export")
	case serviceExported:
		newCondition.Status = corev1.ConditionTrue
		newCondition.Reason = ptr.To("Succeed")
		newCondition.Message = ptr.To("The Service is exported successfully")
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
		if newCondition.Reason != nil && *existingCondition.Reason == *newCondition.Reason {
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
	versionChangePredicates := builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})
	return ctrl.NewControllerManagedBy(mgr).
		For(&k8smcsv1alpha1.ServiceExport{}, versionChangePredicates).
		Named("serviceexport").
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(objectMapFunc), versionChangePredicates).
		Watches(&discovery.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(endpointSliceMapFunc), versionChangePredicates).
		Watches(&mcv1alpha2.ClusterSet{}, handler.EnqueueRequestsFromMapFunc(r.clusterSetMapFunc),
			builder.WithPredicates(statusReadyPredicate)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

// clusterSetMapFunc handles ClusterSet events by enqueuing all ServiceExports
// into the reconciler processing queue.
func (r *ServiceExportReconciler) clusterSetMapFunc(ctx context.Context, a client.Object) []reconcile.Request {
	clusterSet := &mcv1alpha2.ClusterSet{}
	requests := []reconcile.Request{}
	if a.GetNamespace() != r.namespace {
		return requests
	}

	err := r.Client.Get(ctx, types.NamespacedName{Namespace: a.GetNamespace(), Name: a.GetName()}, clusterSet)
	if err == nil {
		if len(clusterSet.Status.Conditions) > 0 && clusterSet.Status.Conditions[0].Status == corev1.ConditionTrue {
			svcExports := &k8smcsv1alpha1.ServiceExportList{}
			r.Client.List(ctx, svcExports)
			for idx := range svcExports.Items {
				svcExport := &svcExports.Items[idx]
				namespacedName := types.NamespacedName{
					Name:      svcExport.GetName(),
					Namespace: svcExport.GetNamespace(),
				}
				req := reconcile.Request{
					NamespacedName: namespacedName,
				}
				requests = append(requests, req)
			}
		}
	} else if apierrors.IsNotFound(err) {
		// All auto-generated resources will be deleted by the ClusterSet controller when a ClusterSet is
		// deleted, so reset caches here.
		r.installedSvcs = cache.NewIndexer(svcInfoKeyFunc, cache.Indexers{})
		r.installedEps = cache.NewIndexer(epInfoKeyFunc, cache.Indexers{})
	}
	return requests
}

// objectMapFunc simply maps all Serivce and Endpoints events to ServiceExports.
// When there are any Service or Endpoints changes, it might be reflected in ResourceExport
// in leader cluster as well, so ServiceExportReconciler also needs to watch
// Service and Endpoints events.
func objectMapFunc(ctx context.Context, a client.Object) []reconcile.Request {
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      a.GetName(),
				Namespace: a.GetNamespace(),
			},
		},
	}
}

func endpointSliceMapFunc(ctx context.Context, a client.Object) []reconcile.Request {
	labels := a.GetLabels()
	svcName := labels[discovery.LabelServiceName]
	mappedObject := types.NamespacedName{}
	if svcName != "" {
		mappedObject.Name = svcName
		mappedObject.Namespace = a.GetNamespace()
	}
	return []reconcile.Request{
		{
			NamespacedName: mappedObject,
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
	re mcv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	kind := constants.ServiceKind
	sinfo := &svcInfo{
		name:       svc.Name,
		namespace:  svc.Namespace,
		clusterIPs: svc.Spec.ClusterIPs,
		ports:      svc.Spec.Ports,
		svcType:    string(svc.Spec.Type),
	}
	r.resetResourceExport(resName, kind, svc, nil, nil, &re)
	existingResExport := &mcv1alpha1.ResourceExport{}
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
	endpoints []discovery.Endpoint,
	ports []discovery.EndpointPort,
	resName string,
	re mcv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	kind := constants.EndpointsKind
	epInfo := &epInfo{
		name:      req.Name,
		namespace: req.Namespace,
		endpoints: endpoints,
		ports:     ports,
	}
	r.resetResourceExport(resName, kind, nil, endpoints, ports, &re)
	existingResExport := &mcv1alpha1.ResourceExport{}
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

func (r *ServiceExportReconciler) resetResourceExport(resName, kind string,
	svc *corev1.Service,
	endpoints []discovery.Endpoint,
	ports []discovery.EndpointPort,
	re *mcv1alpha1.ResourceExport) mcv1alpha1.ResourceExport {
	re.Spec.Kind = kind
	switch kind {
	case constants.ServiceKind:
		re.ObjectMeta.Name = resName
		re.Spec.Service = &mcv1alpha1.ServiceExport{
			ServiceSpec: corev1.ServiceSpec{
				Ports: svc.Spec.Ports,
			},
		}
		re.Labels[constants.SourceKind] = constants.ServiceKind
	case constants.EndpointsKind:
		re.ObjectMeta.Name = resName
		if len(endpoints) > 0 {
			re.Spec.Endpoints = &mcv1alpha1.EndpointsExport{
				Endpoints: endpoints,
				Ports:     ports,
			}
		}
		re.Labels[constants.SourceKind] = constants.EndpointsKind
	}
	return *re
}

func (r *ServiceExportReconciler) updateOrCreateResourceExport(resName string,
	ctx context.Context,
	req ctrl.Request,
	newResExport *mcv1alpha1.ResourceExport,
	existingResExport *mcv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	createResExport := reflect.DeepEqual(*existingResExport, mcv1alpha1.ResourceExport{})
	resNamespaced := types.NamespacedName{Namespace: rc.GetNamespace(), Name: resName}
	if createResExport {
		// We are using Finalizers to implement asynchronous pre-delete hooks.
		// When a ServiceExport is deleted, the corresponding ResourceExport will have non-zero
		// DeletionTimestamp, so Leader controller can still get the deleted ResourceExport object,
		// then it can clean up any external resources like ResourceImport.
		// For more details about using Finalizers, please refer to https://book.kubebuilder.io/reference/using-finalizers.html.
		newResExport.Finalizers = []string{constants.ResourceExportFinalizer}
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

// getEndpointsFromEndpointSlice returns the ready endpoints and ports from all IPv4
// EndpointSlices for the given Service, using the native discovery/v1 types.
// When endpointIPType is ClusterIP it returns early as soon as a ready endpoint is found.
func (r *ServiceExportReconciler) getEndpointsFromEndpointSlice(ctx context.Context, req ctrl.Request) ([]discovery.Endpoint, []discovery.EndpointPort, bool, error) {
	epSliceList := &discovery.EndpointSliceList{}
	err := r.Client.List(ctx, epSliceList, &client.ListOptions{
		LabelSelector: getEndpointSliceLabelSelector(req.Name),
		Namespace:     req.Namespace,
	})
	if err != nil {
		return nil, nil, false, err
	}
	if len(epSliceList.Items) == 0 {
		return nil, nil, false, nil
	}
	var endpoints []discovery.Endpoint
	var ports []discovery.EndpointPort
	for _, eps := range epSliceList.Items {
		if eps.AddressType != discovery.AddressTypeIPv4 {
			continue
		}
		if ports == nil {
			ports = normalizeEndpointPorts(eps.Ports)
		}
		for _, ep := range eps.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				if r.endpointIPType == common.EndpointIPTypeClusterIP {
					return nil, ports, true, nil
				}
				endpoints = append(endpoints, ep)
			}
		}
	}
	return endpoints, ports, len(endpoints) > 0, nil
}

func getResourceExportName(clusterID string, req ctrl.Request, kind string) string {
	return clusterID + "-" + req.Namespace + "-" + req.Name + "-" + kind
}

func getEndpointSliceLabelSelector(svcName string) labels.Selector {
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			discovery.LabelServiceName: svcName,
		},
	}
	selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
	return selector
}

// normalizeEndpointPorts normalizes a slice of EndpointPorts so that a Name
// pointer to an empty string is treated the same as nil. The Kubernetes API
// serializes *string("") with omitempty, so it round-trips as nil; normalizing
// here prevents spurious DeepEqual mismatches and update loops.
func normalizeEndpointPorts(ports []discovery.EndpointPort) []discovery.EndpointPort {
	for i := range ports {
		if ports[i].Name != nil && *ports[i].Name == "" {
			ports[i].Name = nil
		}
	}
	return ports
}

// getClusterIPEndpointAndPorts returns the Service's IPv4 ClusterIPs as discovery.Endpoint
// entries and its ports as discovery.EndpointPort entries, for use with the EndpointSlice path.
func getClusterIPEndpointAndPorts(svc *corev1.Service) ([]discovery.Endpoint, []discovery.EndpointPort) {
	var addresses []string
	for _, ip := range svc.Spec.ClusterIPs {
		if net.ParseIP(ip).To4() == nil {
			continue
		}
		addresses = append(addresses, ip)
	}
	if len(addresses) == 0 {
		return nil, nil
	}
	ready := true
	endpoints := []discovery.Endpoint{{
		Addresses:  addresses,
		Conditions: discovery.EndpointConditions{Ready: &ready},
	}}
	var ports []discovery.EndpointPort
	for _, p := range svc.Spec.Ports {
		name := p.Name
		port := p.Port
		proto := p.Protocol
		ports = append(ports, discovery.EndpointPort{
			Name:        &name,
			Port:        &port,
			Protocol:    &proto,
			AppProtocol: p.AppProtocol,
		})
	}
	return endpoints, normalizeEndpointPorts(ports)
}
