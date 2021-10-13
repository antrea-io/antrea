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
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	mcs "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/internal"
)

type (
	// ResourceExportReconciler reconciles a ResourceExport object
	ResourceExportReconciler struct {
		Client              client.Client
		Scheme              *runtime.Scheme
		localClusterManager *internal.LocalClusterManager
		installedResExports cache.Indexer
	}
)

const (
	// cached indexer
	resExportIndexerByNameKind = "resourceexport.by.namekind"
)

func NewResourceExportReconciler(
	Client client.Client,
	Scheme *runtime.Scheme,
	localClusterManager *internal.LocalClusterManager) *ResourceExportReconciler {
	reconciler := &ResourceExportReconciler{
		Client:              Client,
		Scheme:              Scheme,
		localClusterManager: localClusterManager,
		installedResExports: cache.NewIndexer(resExportIndexerKeyFunc, cache.Indexers{resExportIndexerByNameKind: resExportIndexerByNameKindFunc}),
	}
	return reconciler
}

func resExportIndexerKeyFunc(obj interface{}) (string, error) {
	re := obj.(mcsv1alpha1.ResourceExport)
	return NamespacedName(re.Namespace, re.Name), nil
}

func resExportIndexerByNameKindFunc(obj interface{}) ([]string, error) {
	re := obj.(mcsv1alpha1.ResourceExport)
	return []string{re.Spec.Namespace + re.Spec.Name + re.Spec.ClusterID + re.Spec.Kind}, nil
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For ResourceExport controller, it watches events of ResourceExport resource,
// then create/update/remove ResourceImport resource in leader cluster
// for all ResourceExports which have the same kind, name and namespace
// from member clusters.
func (r *ResourceExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).Infof("reconcile for %s", req.NamespacedName)
	localMgr := *r.localClusterManager
	if localMgr == nil {
		return ctrl.Result{}, errors.New("clusterset has not been initialized properly, no local cluster manager")
	}
	var resExport mcsv1alpha1.ResourceExport
	if err := r.Client.Get(ctx, req.NamespacedName, &resExport); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		re, exist, _ := r.installedResExports.GetByKey(req.NamespacedName.String())
		if !exist {
			klog.Infof("no matched cache for %s", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		existRe := re.(mcsv1alpha1.ResourceExport)
		reList := &mcsv1alpha1.ResourceExportList{}
		err := localMgr.List(ctx, reList, &client.ListOptions{LabelSelector: getLabelSelector(&existRe)})
		if err != nil {
			return ctrl.Result{}, err
		}

		resImportName := getResourceImportName(&existRe)
		if len(reList.Items) == 0 {
			klog.Infof("cleanup ResourceImport %s/%s", req.Namespace, resImportName)
			resImport := &mcsv1alpha1.ResourceImport{ObjectMeta: metav1.ObjectMeta{
				Name:      resImportName,
				Namespace: req.Namespace,
			}}
			err := localMgr.Delete(ctx, resImport, &client.DeleteOptions{})
			if err != nil {
				klog.Errorf("fail to delete ResourceImport %s/%s, err: %v", req.Namespace, resImportName, err)
				if apierrors.IsNotFound(err) {
					r.installedResExports.Delete(re)
					return ctrl.Result{}, nil
				}
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		// should update ResourceImport status when one of ResourceExports is removed?
		if existRe.Spec.Kind == ServiceKind {
			return ctrl.Result{}, nil
		}
		uniqueIndex := existRe.Spec.Namespace + existRe.Spec.Name + existRe.Spec.ClusterID + EndpointsKind
		epExportCache, err := r.installedResExports.ByIndex(resExportIndexerByNameKind, uniqueIndex)
		if err != nil {
			klog.Infof("fail to get cache, err: %v", err)
			return ctrl.Result{}, err
		}
		if len(epExportCache) == 0 {
			klog.Infof("no cache in installedResExports %s", req.NamespacedName)
			return ctrl.Result{}, nil
		} else if len(epExportCache) == 1 {
			epExport := epExportCache[0].(mcsv1alpha1.ResourceExport)
			resImport := &mcsv1alpha1.ResourceImport{}
			err := localMgr.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: resImportName}, resImport)
			if err != nil {
				klog.Errorf("fail to get ResourceImport %s/%s, err: %v", req.Namespace, resImportName, err)
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}
			newResImport, changed := r.refreshResourceImport(&epExport, resImport, false)
			if changed {
				err = localMgr.Update(ctx, newResImport, &client.UpdateOptions{})
				if err != nil {
					klog.Errorf("fail to update ResourceImport %s/%s", req.Namespace, resImportName)
					return ctrl.Result{}, err
				}
			}
			r.installedResExports.Delete(epExport)
			return ctrl.Result{}, nil
		} else {
			// this should never happen.
			return ctrl.Result{}, fmt.Errorf("duplicate Endpoint type of ResourceExport")
		}
	}

	importedResNameSpace := resExport.Labels["sourceNamespace"]
	importedResName := resExport.Labels["sourceName"]
	importedClusterID := resExport.Labels["sourceClusterID"]
	resImportName := getResourceImportName(&resExport)

	var createResImport bool
	existResImport := &mcsv1alpha1.ResourceImport{}
	err := localMgr.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: resImportName}, existResImport)
	if err != nil {
		klog.Errorf("fail to get ResourceImport %s/%s, err: %v", req.Namespace, resImportName, err)
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		existResImport = &mcsv1alpha1.ResourceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resImportName,
				Namespace: req.Namespace,
			},
			Spec: mcsv1alpha1.ResourceImportSpec{
				ClusterIDs: []string{},
				Name:       importedResName,
				Namespace:  importedResNameSpace,
			},
		}
		createResImport = true
	}

	resImport, changed := r.refreshResourceImport(&resExport, existResImport, createResImport)
	if changed {
		if createResImport {
			err = localMgr.Create(ctx, resImport, &client.CreateOptions{})
		} else {
			err = localMgr.Update(ctx, resImport, &client.UpdateOptions{})
		}
	} else {
		r.updateCache(resExport, req)
		return ctrl.Result{}, nil
	}

	if err != nil {
		if createResImport {
			klog.Errorf("fail to create ResourceImport %s/%s,err: %v", req.Namespace, resImportName, err)
			return ctrl.Result{}, err
		} else {
			klog.Errorf("fail to update ResourceImport %s/%s, err: %v", req.Namespace, resImportName, err)
			return ctrl.Result{}, err
		}
	}

	r.updateCache(resExport, req)

	latestResImport := &mcsv1alpha1.ResourceImport{}
	err = localMgr.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: resImportName}, latestResImport)
	if err != nil {
		klog.Errorf("fail to get ResourceImport %s/%s,err: %v", req.Namespace, resImportName, err)
		return ctrl.Result{}, err
	}
	updatedStatus := latestResImport.DeepCopy().Status
	var message string
	if createResImport {
		message = "creation is successful"
	} else {
		message = "update is successful"
	}

	//TODO: should ResourceImport status be updated only by member cluster to tell the leader the service import status?
	updatedStatus.ClusterStatuses = append(updatedStatus.ClusterStatuses, mcsv1alpha1.ResourceImportClusterStatus{
		ClusterID: importedClusterID,
		Conditions: []mcsv1alpha1.ResourceImportCondition{{
			Type:               mcsv1alpha1.ResourceImportSucceeded,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now()),
			Message:            message,
		}},
	})
	latestResImport.Status = updatedStatus
	if err := localMgr.Status().Update(ctx, latestResImport, &client.UpdateOptions{}); err != nil {
		klog.Errorf("fail to update ResourceImport Status %s/%s, err: %v", req.Namespace, resImportName, err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *ResourceExportReconciler) updateCache(resExport mcsv1alpha1.ResourceExport, req ctrl.Request) {
	_, exist, _ := r.installedResExports.GetByKey(req.NamespacedName.String())
	if exist {
		r.installedResExports.Update(resExport)
	} else {
		r.installedResExports.Add(resExport)
	}
}

func (r *ResourceExportReconciler) refreshResourceImport(
	resExport *mcsv1alpha1.ResourceExport,
	resImport *mcsv1alpha1.ResourceImport,
	createResImport bool) (*mcsv1alpha1.ResourceImport, bool) {
	newResImport := resImport.DeepCopy()
	switch resExport.Spec.Kind {
	case ServiceKind:
		newResImport.Spec.Kind = ServiceImportKind
		if createResImport {
			newResImport.Spec.ServiceImport = &mcs.ServiceImport{
				Spec: mcs.ServiceImportSpec{
					Ports: svcPortsConverter(resExport.Spec.Service.ServiceSpec.Ports),
					Type:  mcs.ClusterSetIP,
				},
			}
			return newResImport, true
		}
		convertedPorts := svcPortsConverter(resExport.Spec.Service.ServiceSpec.Ports)
		if !apiequality.Semantic.DeepEqual(newResImport.Spec.ServiceImport.Spec.Ports, convertedPorts) {
			klog.Infof("new ResourceExport ports %v don't match existing ResourceImport Ports %v, skip it", resExport.Spec.Service.ServiceSpec.Ports, newResImport.Spec.ServiceImport.Spec.Ports)
			// TODO: update ResourceExport status to reflect port collision?
		}
		return newResImport, false
	case EndpointsKind:
		newResImport.Spec.Kind = EndpointsKind
		if createResImport {
			newResImport.Spec.Endpoints = &mcsv1alpha1.EndpointsImport{
				Subsets: resExport.Spec.Endpoints.Subsets,
			}
			return newResImport, true
		}
		// check all mateched Endpoints ResourceExport and generate a new EndpointSubset
		newSubsets := []corev1.EndpointSubset{}
		reList := &mcsv1alpha1.ResourceExportList{}
		err := (*r.localClusterManager).List(context.TODO(), reList, &client.ListOptions{
			LabelSelector: getLabelSelector(resExport),
		})
		if err != nil {
			klog.Errorf("fail to list ResourceExports %v, skip update to existing ResourceImport", err)
			return newResImport, false
		}
		for _, re := range reList.Items {
			newSubsets = append(newSubsets, re.Spec.Endpoints.Subsets...)
		}
		newResImport.Spec.Endpoints = &mcsv1alpha1.EndpointsImport{Subsets: newSubsets}
		return newResImport, true
	}
	return newResImport, false
}

// SetupWithManager sets up the controller with the Manager.
func (r *ResourceExportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcsv1alpha1.ResourceExport{}).
		Complete(r)
}

func getLabelSelector(resExport *mcsv1alpha1.ResourceExport) labels.Selector {
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"sourceNamespace": resExport.Spec.Namespace,
			"sourceName":      resExport.Spec.Name,
			"sourceKind":      resExport.Spec.Kind,
		},
	}
	selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
	return selector
}

func svcPortsConverter(svcPort []corev1.ServicePort) []mcs.ServicePort {
	var mcsSP []mcs.ServicePort
	for _, v := range svcPort {
		mcsSP = append(mcsSP, mcs.ServicePort{
			Name:     strconv.Itoa(int(v.Port)) + string(v.Protocol),
			Port:     v.Port,
			Protocol: v.Protocol,
		})
	}
	return mcsSP
}

func getResourceImportName(resExport *mcsv1alpha1.ResourceExport) string {
	return resExport.Spec.Namespace + "-" + resExport.Spec.Name + "-" + strings.ToLower(resExport.Spec.Kind)
}
