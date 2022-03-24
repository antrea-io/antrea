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
	"sort"
	"strconv"
	"strings"

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
		name       string
		namespace  string
		addressIPs []string
		ports      []corev1.EndpointPort
		labels     map[string]string
	}

	// ServiceExportReconciler reconciles a ServiceExport object in the member cluster.
	ServiceExportReconciler struct {
		client.Client
		Scheme                  *runtime.Scheme
		remoteCommonAreaManager *commonarea.RemoteCommonAreaManager
		installedSvcs           cache.Indexer
		installedEps            cache.Indexer
		leaderNamespace         string
		leaderClusterID         string
		localClusterID          string
	}
)

const (
	// cached indexer
	svcIndexerByType = "svc.type"
	epIndexerByLabel = "ep.label"
)

type reason int

const (
	notFound reason = iota
	importedService
)

func NewServiceExportReconciler(
	Client client.Client,
	Scheme *runtime.Scheme,
	remoteCommonAreaManager *commonarea.RemoteCommonAreaManager) *ServiceExportReconciler {
	reconciler := &ServiceExportReconciler{
		Client:                  Client,
		Scheme:                  Scheme,
		remoteCommonAreaManager: remoteCommonAreaManager,
		installedSvcs: cache.NewIndexer(svcInfoKeyFunc, cache.Indexers{
			svcIndexerByType: svcIndexerByTypeFunc,
		}),
		installedEps: cache.NewIndexer(epInfoKeyFunc, cache.Indexers{
			epIndexerByLabel: epIndexerByLabelFunc,
		}),
	}
	return reconciler
}

func svcInfoKeyFunc(obj interface{}) (string, error) {
	svc := obj.(*svcInfo)
	return common.NamespacedName(svc.namespace, svc.name), nil
}

func svcIndexerByTypeFunc(obj interface{}) ([]string, error) {
	return []string{obj.(*svcInfo).svcType}, nil
}

func epInfoKeyFunc(obj interface{}) (string, error) {
	ep := obj.(*epInfo)
	return common.NamespacedName(ep.namespace, ep.name), nil
}

func epIndexerByLabelFunc(obj interface{}) ([]string, error) {
	var info []string
	ep := obj.(*epInfo)
	keys := make([]string, len(ep.labels))
	i := 0
	for k := range ep.labels {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, k := range keys {
		info = append(info, k+ep.labels[k])
	}
	return info, nil
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/finalizers,verbs=update
//+kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceexports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceexports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update
//+kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch;update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For ServiceExport Reconcile, it watches events of ServiceExport resources,
// and also Endpoints/Services resource. It will create/update/remove ResourceExport
// in a leader cluster for corresponding ServiceExport from a member cluster.
func (r *ServiceExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling ServiceExport", "serviceexport", req.NamespacedName)
	svcExportList := &k8smcsv1alpha1.ServiceExportList{}
	err := r.Client.List(ctx, svcExportList, &client.ListOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to list ServiceExport")
		return ctrl.Result{}, err
	}

	// return faster during initilization instead of handling all Service/Endpoint events
	if len(svcExportList.Items) == 0 && len(r.installedSvcs.List()) == 0 {
		klog.InfoS("Skip reconciling, no corresponding ServiceExport")
		return ctrl.Result{}, nil
	}

	if *r.remoteCommonAreaManager == nil {
		klog.InfoS("ClusterSet has not been initialized properly, no remote cluster manager")
		return ctrl.Result{Requeue: true}, nil
	}
	r.localClusterID = string((*r.remoteCommonAreaManager).GetLocalClusterID())
	if len(r.localClusterID) == 0 {
		klog.InfoS("localClusterID is not initialized, skip reconcile")
		return ctrl.Result{Requeue: true}, nil
	}

	var svcExport k8smcsv1alpha1.ServiceExport
	svcObj, svcInstalled, _ := r.installedSvcs.GetByKey(req.String())
	epObj, epInstalled, _ := r.installedEps.GetByKey(req.String())
	svcResExportName := getResourceExportName(r.localClusterID, req, "service")
	epResExportName := getResourceExportName(r.localClusterID, req, "endpoints")

	remoteCluster, err := getRemoteCommonArea(r.remoteCommonAreaManager)
	if err != nil {
		return ctrl.Result{}, err
	}

	r.leaderNamespace = remoteCluster.GetNamespace()
	r.leaderClusterID = string(remoteCluster.GetClusterID())

	svc := &corev1.Service{}
	if err := r.Client.Get(ctx, req.NamespacedName, &svcExport); err != nil {
		klog.V(2).ErrorS(err, "Unable to fetch ServiceExport", "serviceexport", req.String())
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if svcInstalled {
			err = r.handleServiceDeleteEvent(ctx, req, remoteCluster)
			if err != nil {
				return ctrl.Result{}, err
			}
			r.installedSvcs.Delete(svcObj)
		}

		if epInstalled {
			err = r.handleEndpointDeleteEvent(ctx, req, remoteCluster)
			if err != nil {
				return ctrl.Result{}, err
			}
			r.installedEps.Delete(epObj)
		}
		return ctrl.Result{}, nil
	}

	// if corresponding Service doesn't exist, update ServiceExport's status reason to not_found_service,
	// and clean up remote ResourceExport if it's an installed Service.
	err = r.Client.Get(ctx, req.NamespacedName, svc)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if svcInstalled {
				err = r.handleServiceDeleteEvent(ctx, req, remoteCluster)
				if err != nil {
					return ctrl.Result{}, err
				}
				r.installedSvcs.Delete(svcObj)
			}
			err = r.updateSvcExportStatus(ctx, req, notFound)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		} else {
			klog.ErrorS(err, "Failed to get Service ", req.String())
			return ctrl.Result{}, err
		}
	}

	// skip if ServiceExport is trying to export MC Service/Endpoints
	if !svcInstalled || !epInstalled {
		if _, ok := svc.Annotations[common.AntreaMCServiceAnnotation]; ok {
			klog.InfoS("It's not allowed to export the multi-cluster controller auto-generated Service", "service", req.String())
			err = r.updateSvcExportStatus(ctx, req, importedService)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	}

	// We also watch Service and Endpoints events via events mapping function.
	// Need to check cache and compare with cache if there is any change for Service or Endpoints.
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

	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}

	err = r.Client.Get(ctx, req.NamespacedName, ep)
	if err != nil {
		klog.ErrorS(err, "Failed to get Endpoints", "endpoints", req.String())
		if apierrors.IsNotFound(err) && epInstalled {
			err = r.handleEndpointDeleteEvent(ctx, req, remoteCluster)
			if err != nil {
				return ctrl.Result{}, err
			}
			r.installedEps.Delete(epObj)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if epInstalled {
		installedEp := epObj.(*epInfo)
		if apiequality.Semantic.DeepEqual(getEndPointsPorts(ep), installedEp.ports) &&
			apiequality.Semantic.DeepEqual(getEndPointsAddress(ep), installedEp.addressIPs) {
			klog.InfoS("Endpoints has been converted into ResourceExport and no change, skip it", "endpoints",
				req.String(), "resourceexport", epExportNSName)
			epNoChange = true
		}
	}

	if epNoChange && svcNoChange {
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
		err := r.serviceHandler(ctx, req, svc, svcResExportName, re, remoteCluster)
		if err != nil {
			klog.ErrorS(err, "Failed to handle Service change", "service", req.String())
			return ctrl.Result{}, err
		}
	}

	if !epNoChange {
		klog.InfoS("Endpoints have new change, update ResourceExport", "endpoints",
			req.String(), "resourceexport", epExportNSName)
		err := r.endpointsHandler(ctx, req, ep, epResExportName, re, remoteCluster)
		if err != nil {
			klog.ErrorS(err, "Failed to handle Endpoints change", "endpoints", req.String())
			return ctrl.Result{}, err
		}
	}

	if err = r.updateSvcExportAnnotation(&svcExport); err != nil {
		// Ignore the error since it's not critical and we can update in next event.
		klog.ErrorS(err, "Failed to update ServiceExport annotation", "serviceexport", klog.KObj(&svcExport))
	}
	return ctrl.Result{}, nil
}

func (r *ServiceExportReconciler) handleServiceDeleteEvent(ctx context.Context, req ctrl.Request,
	remoteCluster commonarea.RemoteCommonArea) error {
	svcResExportName := getResourceExportName(r.localClusterID, req, "service")
	svcResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcResExportName,
			Namespace: r.leaderNamespace,
		},
	}

	// clean up Service kind of ResourceExport in remote leader cluster
	svcResExportNamespaced := common.NamespacedName(r.leaderNamespace, svcResExportName)
	err := remoteCluster.Delete(ctx, svcResExport, &client.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete ResourceExport in remote cluster", "resourceexport",
			svcResExportNamespaced, "clusterID", r.leaderClusterID)
		return err
	}
	klog.V(2).InfoS("Clean up ResourceExport in remote cluster", "resourceexport", svcResExportNamespaced)
	return nil
}

func (r *ServiceExportReconciler) handleEndpointDeleteEvent(ctx context.Context, req ctrl.Request,
	remoteCluster commonarea.RemoteCommonArea) error {
	epResExportName := getResourceExportName(r.localClusterID, req, "endpoints")
	epResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      epResExportName,
			Namespace: r.leaderNamespace,
		},
	}

	// clean up Endpoints kind of ResourceExport in remote leader cluster
	epResExportNamespaced := common.NamespacedName(r.leaderNamespace, epResExportName)
	err := remoteCluster.Delete(ctx, epResExport, &client.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		klog.ErrorS(err, "Failed to delete ResourceExport in remote cluster", "resourceexport",
			epResExportNamespaced, "clusterID", r.leaderClusterID)
		return err
	}

	klog.V(2).InfoS("Clean up ResourceExport in remote cluster", "resourceexport", epResExportNamespaced)
	return nil
}

func (r *ServiceExportReconciler) updateSvcExportAnnotation(svcExport *k8smcsv1alpha1.ServiceExport) error {
	addAnnotation(svcExport, r.localClusterID)
	if err := r.Client.Update(ctx, svcExport, &client.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}

func (r *ServiceExportReconciler) updateSvcExportStatus(ctx context.Context, req ctrl.Request, cause reason) error {
	svcExport := &k8smcsv1alpha1.ServiceExport{}
	err := r.Client.Get(ctx, req.NamespacedName, svcExport)
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	addAnnotation(svcExport, r.localClusterID)
	now := metav1.Now()
	var res, message *string
	switch cause {
	case notFound:
		res = getStringPointer("not_found_service")
		message = getStringPointer("the Service does not exist")
	case importedService:
		res = getStringPointer("imported_service")
		message = getStringPointer("the Service is imported, not allowed to export")
	default:
		res = getStringPointer("invalid_service")
		message = getStringPointer("the Service is not valid to export")
	}

	svcExportConditions := svcExport.Status.DeepCopy().Conditions
	invalidCondition := k8smcsv1alpha1.ServiceExportCondition{
		Type:               k8smcsv1alpha1.ServiceExportValid,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: &now,
		Reason:             res,
		Message:            message,
	}

	matchedCondition := false
	for n, c := range svcExportConditions {
		if c.Type == k8smcsv1alpha1.ServiceExportValid {
			matchedCondition = true
			svcExportConditions[n] = invalidCondition
			break
		}
	}
	if !matchedCondition {
		svcExportConditions = append(svcExportConditions, invalidCondition)

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
	return ctrl.NewControllerManagedBy(mgr).
		For(&k8smcsv1alpha1.ServiceExport{}).
		Watches(&source.Kind{Type: &corev1.Service{}}, handler.EnqueueRequestsFromMapFunc(objMapFunc)).
		Watches(&source.Kind{Type: &corev1.Endpoints{}}, handler.EnqueueRequestsFromMapFunc(objMapFunc)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

// objMapFunc simply maps all object events to ServiceExport
func objMapFunc(a client.Object) []reconcile.Request {
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
	existResExport := &mcsv1alpha1.ResourceExport{}
	resNamespaced := types.NamespacedName{Namespace: rc.GetNamespace(), Name: resName}
	err := rc.Get(ctx, resNamespaced, existResExport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get ResourceExport", "resourceexport", resNamespaced.String())
			return err
		}
	}
	if err = r.updateOrCreateResourceExport(resName, ctx, req, &re, existResExport, rc); err != nil {
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
	ep *corev1.Endpoints,
	resName string,
	re mcsv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	kind := common.EndpointsKind
	epInfo := &epInfo{
		name:       ep.Name,
		namespace:  ep.Namespace,
		addressIPs: getEndPointsAddress(ep),
		ports:      getEndPointsPorts(ep),
		labels:     ep.Labels,
	}
	r.refreshResourceExport(resName, kind, nil, ep, &re)
	existResExport := &mcsv1alpha1.ResourceExport{}
	resNamespaced := types.NamespacedName{Namespace: rc.GetNamespace(), Name: resName}
	err := rc.Get(ctx, resNamespaced, existResExport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get ResourceExport", "resourceexport", resNamespaced.String())
			return err
		}
	}
	if err = r.updateOrCreateResourceExport(resName, ctx, req, &re, existResExport, rc); err != nil {
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
		newSvcSpec := svc.Spec.DeepCopy()
		var renamedPorts []corev1.ServicePort
		for _, p := range svc.Spec.Ports {
			p.Name = strings.ToLower(string(p.Protocol)) + strconv.Itoa(int(p.Port))
			renamedPorts = append(renamedPorts, p)
		}
		newSvcSpec.Ports = renamedPorts
		re.Spec.Service = &mcsv1alpha1.ServiceExport{
			ServiceSpec: *newSvcSpec,
		}
		re.Labels[common.SourceKind] = common.ServiceKind
	case common.EndpointsKind:
		re.ObjectMeta.Name = resName
		re.Spec.Endpoints = &mcsv1alpha1.EndpointsExport{
			Subsets: common.FilterEndpointSubsets(ep.Subsets),
		}
		re.Labels[common.SourceKind] = common.EndpointsKind
	}
	return *re
}

func (r *ServiceExportReconciler) updateOrCreateResourceExport(resName string,
	ctx context.Context,
	req ctrl.Request,
	newResExport *mcsv1alpha1.ResourceExport,
	existResExport *mcsv1alpha1.ResourceExport,
	rc commonarea.RemoteCommonArea) error {
	createResExport := reflect.DeepEqual(*existResExport, mcsv1alpha1.ResourceExport{})
	resNamespaced := types.NamespacedName{Namespace: rc.GetNamespace(), Name: resName}
	if createResExport {
		newResExport.Finalizers = []string{common.ResourceExportFinalizer}
		klog.InfoS("Creating ResourceExport", "resourceexport", resNamespaced.String())
		err := rc.Create(ctx, newResExport, &client.CreateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to create ResourceExport in leader cluster", "resourceexport", resNamespaced.String())
			return err
		}
	} else {
		newResExport.ObjectMeta.ResourceVersion = existResExport.ObjectMeta.ResourceVersion
		newResExport.Finalizers = existResExport.Finalizers
		err := rc.Update(ctx, newResExport, &client.UpdateOptions{})
		if err != nil {
			klog.ErrorS(err, "Failed to update ResourceExport", "resourceexport", resNamespaced.String())
			return err
		}
	}

	return nil
}

func addAnnotation(svcExport *k8smcsv1alpha1.ServiceExport, localClusterID string) {
	if svcExport.Annotations == nil {
		svcExport.Annotations = make(map[string]string)
	}
	if _, ok := svcExport.Annotations[common.AntreaMCClusterIDAnnotation]; !ok {
		svcExport.Annotations[common.AntreaMCClusterIDAnnotation] = localClusterID
	}
}

func getEndPointsAddress(ep *corev1.Endpoints) []string {
	var epAddrs []string
	for _, s := range ep.Subsets {
		for _, a := range s.Addresses {
			epAddrs = append(epAddrs, a.IP)
		}
	}
	return epAddrs
}

func getEndPointsPorts(ep *corev1.Endpoints) []corev1.EndpointPort {
	var epPorts []corev1.EndpointPort
	for _, s := range ep.Subsets {
		epPorts = append(epPorts, s.Ports...)
	}
	return epPorts
}

func getResourceExportName(clusterID string, req ctrl.Request, kind string) string {
	return clusterID + "-" + req.Namespace + "-" + req.Name + "-" + kind
}

func getStringPointer(str string) *string {
	return &str
}
