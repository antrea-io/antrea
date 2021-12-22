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
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	mcs "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

type (
	// ResourceExportReconciler reconciles a ResourceExport object in the leader cluster.
	ResourceExportReconciler struct {
		client.Client
		Scheme *runtime.Scheme
	}
)

type resReason int

const (
	succeed resReason = iota
	failed
)

func NewResourceExportReconciler(
	Client client.Client,
	Scheme *runtime.Scheme) *ResourceExportReconciler {
	reconciler := &ResourceExportReconciler{
		Client: Client,
		Scheme: Scheme,
	}
	return reconciler
}

//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ResourceExport object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *ResourceExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.InfoS("reconciling ResourceExport", "resourceexport", req.NamespacedName)
	var resExport mcsv1alpha1.ResourceExport
	if err := r.Client.Get(ctx, req.NamespacedName, &resExport); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// We are using Finalizers to implement asynchronous pre-delete hooks.
	// When ResourceExport is deleted, it will have non-zero DeletionTimestamp
	// but controller can still get the deleted ResourceExport object, so we can
	// clean up any external resources like ResourceImport.
	// More details about using Finalizers, please refer to https://book.kubebuilder.io/reference/using-finalizers.html.
	if !resExport.DeletionTimestamp.IsZero() {
		if common.StringExistsInSlice(resExport.Finalizers, common.ResourceExportFinalizer) {
			err := r.handleDeleteEvent(ctx, &resExport)
			if err != nil {
				return ctrl.Result{}, err
			}
			resExport.SetFinalizers(common.RemoveStringFromSlice(resExport.Finalizers, common.ResourceExportFinalizer))
			if err := r.Client.Update(ctx, &resExport, &client.UpdateOptions{}); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, nil
	}

	createResImport, existResImport, err := r.getExistingResImport(ctx, resExport)
	if err != nil {
		return ctrl.Result{}, err
	}

	var changed bool
	resImport := &mcsv1alpha1.ResourceImport{}
	switch resExport.Spec.Kind {
	case common.ServiceKind:
		resImport, changed, err = r.refreshServiceResourceImport(&resExport, existResImport, createResImport)
	case common.EndpointsKind:
		resImport, changed, err = r.refreshEndpointsResourceImport(&resExport, existResImport, createResImport)
	}
	if err != nil {
		r.updateResourceExportStatus(&resExport, failed)
		return ctrl.Result{}, err
	}

	resImportName := getResourceImportName(&resExport)

	if createResImport {
		if err = r.Client.Create(ctx, resImport, &client.CreateOptions{}); err != nil {
			klog.ErrorS(err, "failed to create ResourceImport", "resourceimport", resImportName.String())
			return ctrl.Result{}, err
		}
		r.updateResourceExportStatus(&resExport, succeed)
		klog.InfoS("create ResourceImport successfully", "resourceimport", resImportName.String())
	} else if changed {
		klog.InfoS("update ResourceImport for ResoureExport", "resourceimport", resImportName.String(), "resourceexport", req.NamespacedName)
		if err = r.handleUpdateEvent(ctx, resImport, &resExport); err != nil {
			return ctrl.Result{}, err
		}
		r.updateResourceExportStatus(&resExport, succeed)
	}

	// There might be some changes from ResourceExport triggered reconciling but actually no need to update
	// ResourceImport, we still need to update the ResourceExport status to reflect event have been handled
	// successfully.
	if len(resExport.Status.Conditions) == 0 {
		r.updateResourceExportStatus(&resExport, succeed)
	}

	return ctrl.Result{}, nil
}

func (r *ResourceExportReconciler) handleUpdateEvent(ctx context.Context,
	resImport *mcsv1alpha1.ResourceImport, resExport *mcsv1alpha1.ResourceExport) error {
	resImpName := getResourceImportName(resExport)

	var err error
	if err = r.Client.Update(ctx, resImport, &client.UpdateOptions{}); err != nil {
		klog.ErrorS(err, "failed to update ResourceImport", "resourceimport", resImpName.String())
		return err
	}
	latestResImport := &mcsv1alpha1.ResourceImport{}
	err = r.Client.Get(ctx, resImpName, latestResImport)
	if err != nil {
		klog.ErrorS(err, "failed to get latest ResourceImport", "resourceimport", resImpName.String())
		return err
	}

	newStatus := mcsv1alpha1.ResourceImportClusterStatus{
		ClusterID: resExport.Labels[common.SourceClusterID],
		Conditions: []mcsv1alpha1.ResourceImportCondition{{
			Type:               mcsv1alpha1.ResourceImportSucceeded,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now()),
			Message:            "update is successful",
		}},
	}
	var matchedStatus bool
	for k, s := range latestResImport.Status.ClusterStatuses {
		if s.ClusterID == resExport.Labels[common.SourceClusterID] {
			matchedStatus = true
			latestResImport.Status.ClusterStatuses[k] = newStatus
			break
		}
	}
	if !matchedStatus {
		latestResImport.Status.ClusterStatuses = append(latestResImport.Status.ClusterStatuses, newStatus)
	}
	if err := r.Client.Status().Update(ctx, latestResImport, &client.UpdateOptions{}); err != nil {
		klog.ErrorS(err, "failed to update ResourceImport Status", "resourceimport", resImpName.String())
		return err
	}
	return nil
}

// handleDeleteEvent will either delete the corrsponding ResourceImport if no more ResourceExport exists
// or regenerate ResourceImport's Subsets from latest ResourceExports without Endpoints from
// the deleted ResourceExport.
func (r *ResourceExportReconciler) handleDeleteEvent(ctx context.Context, resExport *mcsv1alpha1.ResourceExport) error {
	reList := &mcsv1alpha1.ResourceExportList{}
	err := r.Client.List(ctx, reList, &client.ListOptions{LabelSelector: getLabelSelector(resExport)})
	if err != nil {
		return err
	}
	resImportName := getResourceImportName(resExport)

	undeleteItems := removeDeletedResourceExports(reList.Items)
	if len(undeleteItems) == 0 {
		err = r.cleanUpResourceImport(ctx, resImportName, resExport)
		if err != nil {
			return err
		}
		return nil
	}
	// should update ResourceImport status when one of ResourceExports is removed?
	if resExport.Spec.Kind == common.ServiceKind {
		return nil
	}
	return r.updateEndpointResourceImport(ctx, resExport, resImportName)
}

func (r *ResourceExportReconciler) cleanUpResourceImport(ctx context.Context,
	resImp types.NamespacedName, re interface{}) error {
	klog.InfoS("cleanup ResourceImport", "resourceimport", resImp.String())
	resImport := &mcsv1alpha1.ResourceImport{ObjectMeta: metav1.ObjectMeta{
		Name:      resImp.Name,
		Namespace: resImp.Namespace,
	}}
	err := r.Client.Delete(ctx, resImport, &client.DeleteOptions{})
	return client.IgnoreNotFound(err)
}

func (r *ResourceExportReconciler) updateEndpointResourceImport(ctx context.Context,
	existRe *mcsv1alpha1.ResourceExport, resImpName types.NamespacedName) error {
	resImport := &mcsv1alpha1.ResourceImport{}
	err := r.Client.Get(ctx, resImpName, resImport)
	if err != nil {
		klog.ErrorS(err, "failed to get ResourceImport", "resourceimport", resImpName)
		return client.IgnoreNotFound(err)
	}
	newResImport, changed, err := r.refreshEndpointsResourceImport(existRe, resImport, false)
	if err != nil {
		return err
	}
	if changed {
		if err = r.handleUpdateEvent(ctx, newResImport, existRe); err != nil {
			return err
		}
	}
	return nil
}

func (r *ResourceExportReconciler) getExistingResImport(ctx context.Context,
	resExport mcsv1alpha1.ResourceExport) (bool, *mcsv1alpha1.ResourceImport, error) {
	importedResNameSpace := resExport.Labels[common.SourceNamespace]
	importedResName := resExport.Labels[common.SourceName]
	var createResImport bool
	existResImport := &mcsv1alpha1.ResourceImport{}
	resImportName := getResourceImportName(&resExport)

	err := r.Client.Get(ctx, resImportName, existResImport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "failed to get ResourceImport", "resourceimport", resImportName.String())
			return createResImport, nil, err
		}
		existResImport = &mcsv1alpha1.ResourceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resImportName.Name,
				Namespace: resImportName.Namespace,
			},
			Spec: mcsv1alpha1.ResourceImportSpec{
				ClusterIDs: []string{},
				Name:       importedResName,
				Namespace:  importedResNameSpace,
			},
		}
		createResImport = true
	}
	return createResImport, existResImport, nil
}

// refreshServiceResourceImport returns a new Service kind of ResourceImport or
// updates existing one to reflect any change from member cluster's ResourceExport.
func (r *ResourceExportReconciler) refreshServiceResourceImport(
	resExport *mcsv1alpha1.ResourceExport,
	resImport *mcsv1alpha1.ResourceImport,
	createResImport bool) (*mcsv1alpha1.ResourceImport, bool, error) {
	newResImport := resImport.DeepCopy()
	newResImport.Spec.Name = resExport.Spec.Name
	newResImport.Spec.Namespace = resExport.Spec.Namespace
	newResImport.Spec.Kind = common.ServiceImportKind
	if createResImport {
		newResImport.Spec.ServiceImport = &mcs.ServiceImport{
			Spec: mcs.ServiceImportSpec{
				Ports: svcPortsConverter(resExport.Spec.Service.ServiceSpec.Ports),
				Type:  mcs.ClusterSetIP,
			},
		}
		return newResImport, true, nil
	}
	// TODO: check ClusterIPs difference if it is being used in ResourceImport later
	convertedPorts := svcPortsConverter(resExport.Spec.Service.ServiceSpec.Ports)
	if !apiequality.Semantic.DeepEqual(newResImport.Spec.ServiceImport.Spec.Ports, convertedPorts) {
		undeletedItems, err := r.getNotDeletedResourceExports(resExport)
		if err != nil {
			klog.ErrorS(err, "failed to list ResourceExports, retry later")
			return newResImport, false, err
		}
		// When there is only one Service ResourceExport, ResourceImport should reflect the change
		// otherwise, it should always return error so controller can retry later assuming users can fix the conflicts
		if len(undeletedItems) == 1 && undeletedItems[0].Name == resExport.Name && undeletedItems[0].Namespace == resExport.Namespace {
			newResImport.Spec.ServiceImport.Spec.Ports = convertedPorts
			return newResImport, true, nil
		} else {
			return newResImport, false, fmt.Errorf("new ResourceExport Ports %v don't match existing ResourceImport Ports %v",
				resExport.Spec.Service.ServiceSpec.Ports, newResImport.Spec.ServiceImport.Spec.Ports)
		}
	}
	return newResImport, false, nil
}

// refreshEndpointsResourceImport returns a new Endpoints kind of ResourceImport or
// updates existing one to reflect any change from member cluster's ResourceExport
func (r *ResourceExportReconciler) refreshEndpointsResourceImport(
	resExport *mcsv1alpha1.ResourceExport,
	resImport *mcsv1alpha1.ResourceImport,
	createResImport bool) (*mcsv1alpha1.ResourceImport, bool, error) {
	newResImport := resImport.DeepCopy()
	newResImport.Spec.Name = resExport.Spec.Name
	newResImport.Spec.Namespace = resExport.Spec.Namespace
	newResImport.Spec.Kind = common.EndpointsKind

	// check corresponding Service type of ResourceExport, if there is any failure,
	// skip adding Endpoints of this ResourceExport and update Endpoint type of
	// ResourceExport's status.
	if resExport.DeletionTimestamp.IsZero() {
		svcResExportName := types.NamespacedName{
			Namespace: resExport.Namespace,
			Name: resExport.Labels[common.SourceClusterID] + "-" + resExport.Labels[common.SourceNamespace] + "-" +
				resExport.Labels[common.SourceName] + "-" + "service",
		}
		svcResExport := &mcsv1alpha1.ResourceExport{}
		err := r.Client.Get(ctx, svcResExportName, svcResExport)
		if err != nil && apierrors.IsNotFound(err) {
			return newResImport, false, fmt.Errorf("failed to get corresponding Service type of ResourceExport: " + svcResExportName.String())
		}
		if len(svcResExport.Status.Conditions) > 0 {
			if svcResExport.Status.Conditions[0].Status != corev1.ConditionTrue {
				return newResImport, false, fmt.Errorf("corresponding Service type of ResourceExport " + svcResExportName.String() +
					"has not been converged successfully, retry later")
			}
		} else {
			return newResImport, false, fmt.Errorf("corresponding Service type of ResourceExport " + svcResExportName.String() +
				"has not been converged yet, retry later")
		}
	}

	if createResImport {
		newResImport.Spec.Endpoints = &mcsv1alpha1.EndpointsImport{
			Subsets: resExport.Spec.Endpoints.Subsets,
		}
		return newResImport, true, nil
	}
	// check all matched Endpoints ResourceExport and generate a new EndpointSubset
	newSubsets := []corev1.EndpointSubset{}
	undeleteItems, err := r.getNotDeletedResourceExports(resExport)
	if err != nil {
		klog.ErrorS(err, "failed to list ResourceExports, retry later")
		return newResImport, false, err
	}
	for _, re := range undeleteItems {
		newSubsets = append(newSubsets, re.Spec.Endpoints.Subsets...)
	}
	newResImport.Spec.Endpoints = &mcsv1alpha1.EndpointsImport{Subsets: newSubsets}
	if apiequality.Semantic.DeepEqual(newResImport.Spec.Endpoints, resImport.Spec.Endpoints) {
		return newResImport, false, nil
	}
	return newResImport, true, nil
}

func (r *ResourceExportReconciler) getNotDeletedResourceExports(resExport *mcsv1alpha1.ResourceExport) ([]mcsv1alpha1.ResourceExport, error) {
	reList := &mcsv1alpha1.ResourceExportList{}
	err := r.Client.List(context.TODO(), reList, &client.ListOptions{
		LabelSelector: getLabelSelector(resExport),
	})
	if err != nil {
		return nil, err
	}
	return removeDeletedResourceExports(reList.Items), nil
}

func (r *ResourceExportReconciler) updateResourceExportStatus(resExport *mcsv1alpha1.ResourceExport, res resReason) {
	newConditions := []mcsv1alpha1.ResourceExportCondition{}
	switch res {
	case succeed:
		newConditions = []mcsv1alpha1.ResourceExportCondition{
			{
				Type:               mcsv1alpha1.ResourceExportSucceeded,
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "",
				Message:            "",
			},
		}
	case failed:
		newConditions = []mcsv1alpha1.ResourceExportCondition{
			{
				Type:               mcsv1alpha1.ResourceExportFailure,
				Status:             corev1.ConditionFalse,
				LastTransitionTime: metav1.Now(),
				Reason:             "converge_failure",
				Message:            "ResourceExport can't be converged to ResourceImport",
			},
		}
	}

	resExport.Status = mcsv1alpha1.ResourceExportStatus{
		Conditions: newConditions,
	}
	err := r.Client.Status().Update(ctx, resExport)
	if err != nil {
		klog.ErrorS(err, "failed to update ResourceExport status", "resourceexport", klog.KObj(resExport))
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ResourceExportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// ignore status update event via GenerationChangedPredicate
	instance := predicate.GenerationChangedPredicate{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcsv1alpha1.ResourceExport{}).
		WithEventFilter(instance).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: common.DefaultWorkerCount,
		}).
		Complete(r)
}

func getLabelSelector(resExport *mcsv1alpha1.ResourceExport) labels.Selector {
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			common.SourceNamespace: resExport.Spec.Namespace,
			common.SourceName:      resExport.Spec.Name,
			common.SourceKind:      resExport.Spec.Kind,
		},
	}
	selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
	return selector
}

func svcPortsConverter(svcPort []corev1.ServicePort) []mcs.ServicePort {
	var mcsSP []mcs.ServicePort
	for _, v := range svcPort {
		mcsSP = append(mcsSP, mcs.ServicePort{
			Name:     strconv.Itoa(int(v.Port)) + strings.ToLower(string(v.Protocol)),
			Port:     v.Port,
			Protocol: v.Protocol,
		})
	}
	return mcsSP
}

func getResourceImportName(resExport *mcsv1alpha1.ResourceExport) types.NamespacedName {
	return types.NamespacedName{
		Namespace: resExport.Namespace,
		Name:      resExport.Spec.Namespace + "-" + resExport.Spec.Name + "-" + strings.ToLower(resExport.Spec.Kind),
	}
}

// We use finalizers as ResourceExport pre-delete hooks, which means when
// we list the ResourceExports, it will also return deleted items.
// removeDeletedResourceExports remove any ResourceExports with non-zero DeletionTimestamp
// which is actually deleted object.
func removeDeletedResourceExports(items []mcsv1alpha1.ResourceExport) []mcsv1alpha1.ResourceExport {
	undeleteItems := []mcsv1alpha1.ResourceExport{}
	for _, i := range items {
		if i.DeletionTimestamp.IsZero() {
			undeleteItems = append(undeleteItems, i)
		}
	}
	return undeleteItems
}
