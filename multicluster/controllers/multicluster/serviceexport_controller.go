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
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/internal"
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

	// ServiceExportReconciler reconciles a ServiceExport object
	ServiceExportReconciler struct {
		Client               client.Client
		Scheme               *runtime.Scheme
		remoteClusterManager *internal.RemoteClusterManager
		installedSvcs        cache.Indexer
		installedEps         cache.Indexer
	}
)

const (
	// cached indexer
	svcIndexerByType                     = "service.by.type"
	epIndexerByLabel                     = "endpoints.by.label"
	nodeIndexerByServiceName             = "node.by.serviceName"
	resExportIndexerByKind               = "resourceexport.by.kind"
	resExportIndexerByNameSpacedNameKind = "resourceexport.by.namespacedNameKind"
)

var leaderNamespace string
var leaderClusterID string

func NewServiceExportReconciler(
	Client client.Client,
	Scheme *runtime.Scheme,
	remoteClusterManager *internal.RemoteClusterManager) *ServiceExportReconciler {
	reconciler := &ServiceExportReconciler{
		Client:               Client,
		Scheme:               Scheme,
		remoteClusterManager: remoteClusterManager,
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
	return NamespacedName(svc.namespace, svc.name), nil
}

func svcIndexerByTypeFunc(obj interface{}) ([]string, error) {
	return []string{obj.(*svcInfo).svcType}, nil
}

func epInfoKeyFunc(obj interface{}) (string, error) {
	ep := obj.(*epInfo)
	return NamespacedName(ep.namespace, ep.name), nil
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
//+kubebuilder:rbac:groups="multicluster.x-k8s.io",resources=serviceexports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update
//+kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch;update
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For ServiceExport controller, it watches events of ServiceExport resource, and also
// Endpoints/Services resource if they has desired label 'antrea.io/multi-cluster'.
// It will create/update/remove ResourceExport resource in leader cluster
// for corresponding ServiceExport in member cluster.
func (r *ServiceExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).Infof("reconcile for %s", req.NamespacedName)
	if *r.remoteClusterManager == nil {
		return ctrl.Result{}, errors.New("clusterset has not been initialized properly, no remote cluster manager")
	}
	clusterID := string((*r.remoteClusterManager).GetLocalClusterID())
	if len(clusterID) == 0 {
		return ctrl.Result{}, errors.New("local ClusterID is not initialized, skip reconcile")
	}

	var svcExport k8smcsv1alpha1.ServiceExport
	key := NamespacedName(req.Namespace, req.Name)
	svcObj, svcInstalled, _ := r.installedSvcs.GetByKey(key)
	epObj, epInstalled, _ := r.installedEps.GetByKey(key)
	resExportBaseName := clusterID + "-" + req.Namespace + "-" + req.Name
	svcResExportName := resExportBaseName + "-" + strings.ToLower(ServiceKind)
	epResExportName := resExportBaseName + "-" + strings.ToLower(EndpointsKind)

	remoteClusters := (*r.remoteClusterManager).GetRemoteClusters()
	if len(remoteClusters) <= 0 {
		klog.Warningf("no available remote cluster to write for resource %s/%s, please check your cluster set configuration", req.Namespace, req.Name)
		return ctrl.Result{}, errors.New("clusterset has not been initialized properly, no remote cluster manager")
	}

	// we should only have one remote leader cluster for demo purpose
	// so check and pass the first remote cluster only to *Handler.
	var remoteCluster internal.RemoteCluster
	for _, c := range remoteClusters {
		remoteCluster = c
		break
	}

	leaderNamespace = remoteCluster.GetNamespace()
	leaderClusterID = string(remoteCluster.GetClusterID())

	svc := &corev1.Service{}
	if err := r.Client.Get(ctx, req.NamespacedName, &svcExport); err != nil {
		//klog.V(2).Infof("unable to fetch ServiceExport %s/%s, err: %v", req.Namespace, req.Name, err)
		klog.Infof("unable to fetch ServiceExport %s/%s, err: %v", req.Namespace, req.Name, err)
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// cleanup labels of Service so we don't watch service event anymore
		err := r.Client.Get(ctx, req.NamespacedName, svc)
		if err == nil {
			delete(svc.Labels, antreaMcsLabel)
			// ignore error since the service event will be triggered again, then here we can delete in another time.
			_ = r.Client.Update(ctx, svc)
		} else {
			klog.Warningf("fail to get service %v", req.NamespacedName, err)
		}

		svcResExport := &mcsv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name: svcResExportName,
			},
		}
		epResExport := &mcsv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name: epResExportName,
			},
		}

		// clean up Service/Endpoints kind of ResourceExport in remote leader cluster
		svcResExport.Namespace = leaderNamespace
		epResExport.Namespace = leaderNamespace
		err = remoteCluster.Delete(ctx, svcResExport, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			klog.Warningf("fail to delete ResourceExport %s/%s in remote cluster %s, err: %v", leaderNamespace, svcResExportName, leaderClusterID, err)
			return ctrl.Result{}, err
		}
		if svcInstalled {
			r.installedSvcs.Delete(svcObj)
		}

		err = remoteCluster.Delete(ctx, epResExport, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			klog.Warningf("fail to delete ResourceExport %s/%s in remote cluster, err: %v", req.Namespace, epResExportName, leaderClusterID, err)
			return ctrl.Result{}, err
		}

		if epInstalled {
			r.installedEps.Delete(epObj)
		}
		//klog.V(2).Infof("deleted ResourceExport  %s/%s and %s/%s in remote cluster", req.Namespace, svcResExportName, req.Namespace, epResExportName)
		klog.Infof("deleted ResourceExport  %s/%s and %s/%s in remote cluster", req.Namespace, svcResExportName, req.Namespace, epResExportName)
		return ctrl.Result{}, nil
	}

	// check if corresponding service exists or not, if it's deleted
	// then need to clean up ServiceExport
	err := r.Client.Get(ctx, req.NamespacedName, svc)
	if err != nil {
		if apierrors.IsNotFound(err) {
			svcExport := &k8smcsv1alpha1.ServiceExport{}
			err = r.Client.Get(ctx, req.NamespacedName, svcExport)
			if err != nil {
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}
			now := metav1.Now()
			svcExportConditions := svcExport.Status.DeepCopy().Conditions
			invalidCondition := k8smcsv1alpha1.ServiceExportCondition{
				Type:               k8smcsv1alpha1.ServiceExportValid,
				Status:             corev1.ConditionFalse,
				LastTransitionTime: &now,
				Reason:             GetPointer("invalid_service"),
				Message:            GetPointer("corresponding Service does not exist"),
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
				klog.Errorf("fail to update ServiceExport %s/%s, err: %v", req.Namespace, req.Name, err)
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}
		} else {
			klog.Errorf("fail to get Service %s/%s, err: %v", req.Namespace, req.Name, err)
			return ctrl.Result{}, err
		}
	}

	// we also watch Service and Endpoints events via events mapping function
	// need to check cache and compare with cache if there is any change for Service or Endpoints
	var svcNoChange, epNoChange bool
	if svcInstalled {
		installedSvc := svcObj.(*svcInfo)
		if reflect.DeepEqual(svc.Spec.Ports, installedSvc.ports) &&
			reflect.DeepEqual(svc.Spec.ClusterIPs, installedSvc.clusterIPs) {
			klog.Infof("Service %s/%s has been converted into ResourceExport %s/%s and no change, skip it", svc.Namespace, svc.Name, leaderNamespace, svcResExportName)
			svcNoChange = true
		}
	}

	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Labels: map[string]string{
				SourceServiceType: string(corev1.ServiceTypeNodePort),
			},
		},
	}

	if svc.Spec.Type == corev1.ServiceTypeNodePort {
		// Build up Endpoint with Node ip and nodePort for NodePort service.
		nodes := &corev1.NodeList{}
		opt := &client.ListOptions{Raw: &metav1.ListOptions{FieldSelector: "spec.unschedulable=false"}}
		err := r.Client.List(ctx, nodes, opt)
		if err != nil {
			return ctrl.Result{}, err
		}
		var addresses []corev1.EndpointAddress
		for _, n := range nodes.Items {
			for _, a := range n.Status.Addresses {
				// prefer to use external IP?
				if a.Type == corev1.NodeExternalIP {
					addresses = append(addresses, corev1.EndpointAddress{IP: a.Address})
					break
				}
				if a.Type == corev1.NodeInternalIP {
					addresses = append(addresses, corev1.EndpointAddress{IP: a.Address})
					break
				}
			}
		}

		var ports []corev1.EndpointPort
		for _, p := range svc.Spec.Ports {
			ports = append(ports, corev1.EndpointPort{
				Name:     strings.ToLower(string(p.Protocol)) + strconv.Itoa(int(p.Port)),
				Port:     p.NodePort,
				Protocol: p.Protocol,
			})
		}
		ep.Subsets = []corev1.EndpointSubset{{Addresses: addresses, Ports: ports}}
	} else {
		err = r.Client.Get(ctx, req.NamespacedName, ep)
		if err != nil {
			klog.Errorf("fail to get Endpoints %s/%s, err: %v", svcExport.Namespace, svcExport.Name, err)
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	if epInstalled {
		installedEp := epObj.(*epInfo)
		if reflect.DeepEqual(getEndPointsPorts(ep), installedEp.ports) &&
			reflect.DeepEqual(getEndPointsAddress(ep), installedEp.addressIPs) {
			klog.Infof("Endpoints %s/%s has been converted into ResourceExport %s/%s and no change, skip it", ep.Namespace, ep.Name, leaderNamespace, epResExportName)
			epNoChange = true
		}
	}

	if epNoChange && svcNoChange {
		return ctrl.Result{}, nil
	}

	re := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Labels: map[string]string{
				"sourceName":      req.Name,
				"sourceNamespace": req.Namespace,
				"sourceClusterID": clusterID,
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: clusterID,
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}

	if !svcNoChange {
		klog.Infof("Service %s/%s has new changes, apply into ResourceExport %s/%s", svc.Namespace, svc.Name, leaderNamespace, svcResExportName)
		err := r.serviceHandler(ctx, req, svc, svcResExportName, re, remoteCluster)
		if err != nil {
			klog.Infof("fail to handle service change %s/%s, err: %v", svc.Namespace, svc.Name, err)
			return ctrl.Result{}, err
		}
	}

	if !epNoChange {
		klog.Infof("Endpoints %s/%s have new change, apply into ResourceExport %s/%s", ep.Namespace, ep.Name, leaderNamespace, epResExportName)
		err := r.endpointsHandler(ctx, req, ep, epResExportName, re, remoteCluster)
		if err != nil {
			klog.Infof("fail to handle service change %s/%s, err: %v", svc.Namespace, svc.Name, err)
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceExportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&k8smcsv1alpha1.ServiceExport{}).
		Watches(&source.Kind{Type: &corev1.Service{}}, handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
			if _, ok := a.(*corev1.Service).Labels[antreaMcsLabel]; ok {
				// events mapping from Service to ServiceExport
				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      a.GetName(),
							Namespace: a.GetNamespace(),
						},
					},
				}
			}
			return nil
		})).
		Watches(&source.Kind{Type: &corev1.Endpoints{}}, handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
			if _, ok := a.(*corev1.Endpoints).Labels[antreaMcsLabel]; ok {
				// events mapping from Endpoints to ServiceExport
				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      a.GetName(),
							Namespace: a.GetNamespace(),
						},
					},
				}
			}
			return nil
		})).Complete(r)
}

// serviceHandler handle service related change
// - ClusterIP: update corresponding ResourceExport only when ClusterIP or Ports change.
// - NodePort: update corresponding ResourceExport only when ClusterIP or Ports change.
// ...
func (r *ServiceExportReconciler) serviceHandler(
	ctx context.Context,
	req ctrl.Request,
	svc *corev1.Service,
	resName string,
	re mcsv1alpha1.ResourceExport,
	rc internal.RemoteCluster) error {
	kind := ServiceKind
	sinfo := &svcInfo{
		name:       svc.Name,
		namespace:  svc.Namespace,
		clusterIPs: svc.Spec.ClusterIPs,
		ports:      svc.Spec.Ports,
		svcType:    string(svc.Spec.Type),
	}
	r.refreshResourceExport(resName, kind, svc, nil, &re)
	existResExport := &mcsv1alpha1.ResourceExport{}
	err := rc.Get(ctx, types.NamespacedName{Namespace: leaderNamespace, Name: resName}, existResExport)
	if err != nil {
		klog.Errorf("fail to get ResourceExport %s/%s, err: %v", leaderNamespace, resName, err)
		if !apierrors.IsNotFound(err) {
			return err
		}
	}
	if err = r.updateOrCreateResourceExport(resName, ctx, req, &re, existResExport, rc); err != nil {
		return err
	}
	if svc.Labels != nil {
		svc.Labels[antreaMcsLabel] = "true"
	} else {
		svc.Labels = map[string]string{antreaMcsLabel: "true"}
	}
	// update Service's label with `antrea.io/multi-cluster` so we can watch Service's events via event mapping function.
	if err := r.Client.Update(ctx, svc); err != nil {
		klog.Infof("fail to update Service %s/%s's labels, err: %v", svc.Namespace, svc.Name, err)
	}
	r.installedSvcs.Add(sinfo)
	return nil
}

// endpointsHandler handle Endpoints related change
// - update corresponding ResourceExport only when Ports or Addresses IP change.
func (r *ServiceExportReconciler) endpointsHandler(
	ctx context.Context,
	req ctrl.Request,
	ep *corev1.Endpoints,
	resName string,
	re mcsv1alpha1.ResourceExport,
	rc internal.RemoteCluster) error {
	kind := EndpointsKind
	epInfo := &epInfo{
		name:       ep.Name,
		namespace:  ep.Namespace,
		addressIPs: getEndPointsAddress(ep),
		ports:      getEndPointsPorts(ep),
		labels:     ep.Labels,
	}
	r.refreshResourceExport(resName, kind, nil, ep, &re)
	existResExport := &mcsv1alpha1.ResourceExport{}
	err := rc.Get(ctx, types.NamespacedName{Namespace: leaderNamespace, Name: resName}, existResExport)
	if err != nil {
		klog.Errorf("fail to get ResourceExport %s/%s, err: %v", leaderNamespace, resName, err)
		if !apierrors.IsNotFound(err) {
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
	case ServiceKind:
		re.ObjectMeta.Name = resName
		newSvcSpec := svc.Spec.DeepCopy()
		var renamedPorts []corev1.ServicePort
		// rename port to protocol+port
		for _, p := range svc.Spec.Ports {
			p.Name = strings.ToLower(string(p.Protocol)) + strconv.Itoa(int(p.Port))
			renamedPorts = append(renamedPorts, p)
		}
		newSvcSpec.Ports = renamedPorts
		re.Spec.Service = &mcsv1alpha1.ServiceExport{
			ServiceSpec: *newSvcSpec,
		}
		re.Labels["sourceKind"] = ServiceKind
	case EndpointsKind:
		re.ObjectMeta.Name = resName
		if ep.Labels[SourceServiceType] == string(corev1.ServiceTypeNodePort) {
			re.ObjectMeta.Labels[SourceServiceType] = string(corev1.ServiceTypeNodePort)
		}
		re.Spec.Endpoints = &mcsv1alpha1.EndpointsExport{
			Subsets: ep.Subsets,
		}
		re.Labels["sourceKind"] = EndpointsKind
	}
	return *re
}

func (r *ServiceExportReconciler) updateOrCreateResourceExport(resName string,
	ctx context.Context,
	req ctrl.Request,
	newResExport *mcsv1alpha1.ResourceExport,
	existResExport *mcsv1alpha1.ResourceExport,
	rc internal.RemoteCluster) error {
	createResExport := reflect.DeepEqual(*existResExport, mcsv1alpha1.ResourceExport{})
	if createResExport {
		klog.Infof("creating ResourceExport %s/%s", leaderNamespace, resName)
		err := rc.Create(ctx, newResExport, &client.CreateOptions{})
		if err != nil {
			klog.Errorf("fail to create ResourceExport %s/%s in leader cluster,err: %v", leaderNamespace, resName, err)
			return err
		}
	} else {
		newResExport.ObjectMeta.ResourceVersion = existResExport.ObjectMeta.ResourceVersion
		err := rc.Update(ctx, newResExport, &client.UpdateOptions{})
		if err != nil {
			klog.Infof("fail to update ResourceExport %s/%s, err:%v", leaderNamespace, resName, err)
			return err
		}
	}

	var message string
	if createResExport {
		message = "creation is successful"
	} else {
		message = "update is successful"
	}

	// ignore status update failure?
	latestResExport := &mcsv1alpha1.ResourceExport{}
	err := rc.Get(ctx, types.NamespacedName{Namespace: leaderNamespace, Name: resName}, latestResExport)
	if err != nil {
		klog.Infof("fail to get ResourceExport %v", err)
		return nil
	}
	latestResExport.Status.Conditions = []mcsv1alpha1.ResourceExportCondition{{
		Type:               mcsv1alpha1.ResourceExportSucceeded,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now()),
		Message:            message,
	}}
	err = rc.Status().Update(ctx, latestResExport, &client.UpdateOptions{})
	if err != nil {
		klog.Infof("fail to update ResourceExport's Status %s/%s,err:%v", leaderNamespace, resName, err)
	}
	return nil
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

func GetPointer(str string) *string {
	t := str
	return &t
}
