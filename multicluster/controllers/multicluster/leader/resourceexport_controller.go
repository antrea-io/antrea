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

package leader

import (
	"context"
	"fmt"
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

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
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
	client client.Client,
	scheme *runtime.Scheme) *ResourceExportReconciler {
	reconciler := &ResourceExportReconciler{
		Client: client,
		Scheme: scheme,
	}
	return reconciler
}

// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// Reconcile will process all kinds of ResourceExport. Service and Endpoint kinds of ResourceExport
// will be handled in this file, and all other kinds will have their own handler files, eg: newkind_handler.go
func (r *ResourceExportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(2).InfoS("Reconciling ResourceExport", "resourceexport", req.NamespacedName)
	var resExport mcsv1alpha1.ResourceExport
	if err := r.Client.Get(ctx, req.NamespacedName, &resExport); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	switch resExport.Spec.Kind {
	case constants.ServiceKind:
		klog.V(2).InfoS("Reconciling Service type of ResourceExport", "resourceexport", req.NamespacedName)
	case constants.EndpointsKind:
		klog.V(2).InfoS("Reconciling Endpoint type of ResourceExport", "resourceexport", req.NamespacedName)
	case constants.AntreaClusterNetworkPolicyKind:
		klog.V(2).InfoS("Reconciling AntreaClusterNetworkPolicy type of ResourceExport", "resourceexport", req.NamespacedName)
	case constants.ClusterInfoKind:
		return r.handleClusterInfo(ctx, req, resExport)
	default:
		klog.InfoS("It's not expected kind, skip reconciling ResourceExport", "resourceexport", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// We are using Finalizers to implement asynchronous pre-delete hooks.
	// When a ResourceExport is deleted, it will have non-zero DeletionTimestamp
	// but controller can still get the deleted ResourceExport object, so it can
	// clean up any replicated resources like ResourceImport.
	// For more details about using Finalizers, please refer to https://book.kubebuilder.io/reference/using-finalizers.html.
	if !resExport.DeletionTimestamp.IsZero() {
		if common.StringExistsInSlice(resExport.Finalizers, constants.ResourceExportFinalizer) {
			err := r.handleDeleteEvent(ctx, &resExport)
			if err != nil {
				return ctrl.Result{}, err
			}
			return r.deleteResourceExport(&resExport)
		}
		return ctrl.Result{}, nil
	}

	createResImport, existingResImport, err := r.getExistingResImport(ctx, resExport)
	if err != nil {
		return ctrl.Result{}, err
	}

	var changed bool
	resImport := &mcsv1alpha1.ResourceImport{}
	switch resExport.Spec.Kind {
	case constants.ServiceKind:
		resImport, changed, err = r.refreshServiceResourceImport(&resExport, existingResImport, createResImport)
	case constants.EndpointsKind:
		resImport, changed, err = r.refreshEndpointsResourceImport(&resExport, existingResImport, createResImport)
	case constants.AntreaClusterNetworkPolicyKind:
		resImport, changed, err = r.refreshACNPResourceImport(&resExport, existingResImport, createResImport)
	}
	if err != nil {
		r.updateResourceExportStatus(&resExport, failed)
		return ctrl.Result{}, err
	}

	resImportName := GetResourceImportName(&resExport)

	if createResImport {
		if err = r.Client.Create(ctx, resImport, &client.CreateOptions{}); err != nil {
			klog.ErrorS(err, "Failed to create ResourceImport", "resourceimport", resImportName.String())
			return ctrl.Result{}, err
		}
		r.updateResourceExportStatus(&resExport, succeed)
		klog.V(2).InfoS("ResourceImport is created successfully", "resourceimport", resImportName.String())
	} else if changed {
		klog.V(2).InfoS("Updating ResourceImport for ResoureExport", "resourceimport", resImportName.String(), "resourceexport", req.NamespacedName)
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
	resImpName := GetResourceImportName(resExport)

	var err error
	if err = r.Client.Update(ctx, resImport, &client.UpdateOptions{}); err != nil {
		klog.ErrorS(err, "Failed to update ResourceImport", "resourceimport", resImpName.String())
		return err
	}
	latestResImport := &mcsv1alpha1.ResourceImport{}
	err = r.Client.Get(ctx, resImpName, latestResImport)
	if err != nil {
		klog.ErrorS(err, "Failed to get latest ResourceImport", "resourceimport", resImpName.String())
		return err
	}

	newStatus := mcsv1alpha1.ResourceImportClusterStatus{
		ClusterID: resExport.Labels[constants.SourceClusterID],
		Conditions: []mcsv1alpha1.ResourceImportCondition{{
			Type:               mcsv1alpha1.ResourceImportSucceeded,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now()),
			Message:            "update is successful",
		}},
	}
	var matchedStatus bool
	for k, s := range latestResImport.Status.ClusterStatuses {
		if s.ClusterID == resExport.Labels[constants.SourceClusterID] {
			matchedStatus = true
			latestResImport.Status.ClusterStatuses[k] = newStatus
			break
		}
	}
	if !matchedStatus {
		latestResImport.Status.ClusterStatuses = append(latestResImport.Status.ClusterStatuses, newStatus)
	}
	if err := r.Client.Status().Update(ctx, latestResImport, &client.SubResourceUpdateOptions{}); err != nil {
		klog.ErrorS(err, "Failed to update ResourceImport Status", "resourceimport", resImpName.String())
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
	resImportName := GetResourceImportName(resExport)
	klog.V(2).InfoS("Deleting ResourceImport created by ResourceExport", "resourceimport", resImportName.String(), "resourceexport", resExport.Name)

	undeleteItems := RemoveDeletedResourceExports(reList.Items)
	if len(undeleteItems) == 0 {
		err = r.cleanUpResourceImport(ctx, resImportName, resExport)
		if err != nil {
			return err
		}
		return nil
	}
	// should update ResourceImport status when one of ResourceExports is removed?
	if resExport.Spec.Kind == constants.ServiceKind {
		return nil
	}
	return r.updateEndpointResourceImport(ctx, resExport, resImportName)
}

func (r *ResourceExportReconciler) cleanUpResourceImport(ctx context.Context,
	resImp types.NamespacedName, re interface{}) error {
	klog.InfoS("Cleaning up ResourceImport", "resourceimport", resImp.String())
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
		klog.ErrorS(err, "Failed to get ResourceImport", "resourceimport", resImpName)
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
	importedResNamespace := resExport.Labels[constants.SourceNamespace]
	importedResName := resExport.Labels[constants.SourceName]
	var createResImport bool
	existResImport := &mcsv1alpha1.ResourceImport{}
	resImportName := GetResourceImportName(&resExport)

	err := r.Client.Get(ctx, resImportName, existResImport)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get ResourceImport", "resourceimport", resImportName.String())
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
				Namespace:  importedResNamespace,
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
	newResImport.Spec.Kind = constants.ServiceImportKind
	if createResImport {
		newResImport.Spec.ServiceImport = &mcs.ServiceImport{
			Spec: mcs.ServiceImportSpec{
				Ports: SvcPortsConverter(resExport.Spec.Service.ServiceSpec.Ports),
				Type:  mcs.ClusterSetIP,
			},
		}
		return newResImport, true, nil
	}
	// TODO: check ClusterIPs difference if it is being used in ResrouceImport later
	convertedPorts := SvcPortsConverter(resExport.Spec.Service.ServiceSpec.Ports)
	if !apiequality.Semantic.DeepEqual(newResImport.Spec.ServiceImport.Spec.Ports, convertedPorts) {
		undeletedItems, err := r.getNotDeletedResourceExports(resExport)
		if err != nil {
			klog.ErrorS(err, "Failed to list ResourceExports, retry later")
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
	newResImport.Spec.Kind = constants.EndpointsKind

	// check corresponding Service type of ResourceExport, if there is any failure,
	// skip adding Endpoints of this ResourceExport and update Endpoint type of
	// ResourceExport's status.
	if resExport.DeletionTimestamp.IsZero() {
		svcResExportName := types.NamespacedName{
			Namespace: resExport.Namespace,
			Name: resExport.Labels[constants.SourceClusterID] + "-" + resExport.Labels[constants.SourceNamespace] + "-" +
				resExport.Labels[constants.SourceName] + "-" + "service",
		}
		svcResExport := &mcsv1alpha1.ResourceExport{}
		err := r.Client.Get(context.Background(), svcResExportName, svcResExport)
		if err != nil && apierrors.IsNotFound(err) {
			return newResImport, false, fmt.Errorf("failed to get corresponding Service type of ResourceExport: " + svcResExportName.String())
		}
		if len(svcResExport.Status.Conditions) > 0 {
			if svcResExport.Status.Conditions[0].Status != corev1.ConditionTrue {
				err := fmt.Errorf("the Service type of ResourceExport %s has not been converged successfully, retry later", svcResExportName.String())
				return newResImport, false, err
			}
		} else {
			err := fmt.Errorf("the Service type of ResourceExport %s has not been converged yet, retry later", svcResExportName.String())
			return newResImport, false, err
		}
	}

	if createResImport {
		newResImport.Spec.Endpoints = &mcsv1alpha1.EndpointsImport{
			Subsets: resExport.Spec.Endpoints.Subsets,
		}
		return newResImport, true, nil
	}
	// check all matched Endpoints ResourceExport and generate a new EndpointSubset
	var newSubsets []corev1.EndpointSubset
	undeleteItems, err := r.getNotDeletedResourceExports(resExport)
	if err != nil {
		klog.ErrorS(err, "Failed to list ResourceExports, retry later")
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

func (r *ResourceExportReconciler) refreshACNPResourceImport(
	resExport *mcsv1alpha1.ResourceExport,
	resImport *mcsv1alpha1.ResourceImport,
	createResImport bool) (*mcsv1alpha1.ResourceImport, bool, error) {
	newResImport := resImport.DeepCopy()
	newResImport.Spec.Name = resExport.Spec.Name
	newResImport.Spec.Namespace = resExport.Spec.Namespace
	newResImport.Spec.Kind = constants.AntreaClusterNetworkPolicyKind
	if createResImport {
		newResImport.Spec.ClusterNetworkPolicy = resExport.Spec.ClusterNetworkPolicy
		return newResImport, true, nil
	}
	if !apiequality.Semantic.DeepEqual(resExport.Spec.ClusterNetworkPolicy, resImport.Spec.ClusterNetworkPolicy) {
		undeletedItems, err := r.getNotDeletedResourceExports(resExport)
		if err != nil {
			klog.ErrorS(err, "Failed to list ResourceExports for ACNP, retry later")
			return newResImport, false, err
		}
		if len(undeletedItems) == 1 && undeletedItems[0].Name == resExport.Name && undeletedItems[0].Namespace == resExport.Namespace {
			newResImport.Spec.ClusterNetworkPolicy = resExport.Spec.ClusterNetworkPolicy
			return newResImport, true, nil
		}
	}
	return newResImport, false, nil
}

func (r *ResourceExportReconciler) getNotDeletedResourceExports(resExport *mcsv1alpha1.ResourceExport) ([]mcsv1alpha1.ResourceExport, error) {
	reList := &mcsv1alpha1.ResourceExportList{}
	err := r.Client.List(context.TODO(), reList, &client.ListOptions{
		LabelSelector: getLabelSelector(resExport),
	})
	if err != nil {
		return nil, err
	}
	return RemoveDeletedResourceExports(reList.Items), nil
}

func (r *ResourceExportReconciler) updateResourceExportStatus(resExport *mcsv1alpha1.ResourceExport, res resReason) {
	var newConditions []mcsv1alpha1.ResourceExportCondition
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
				Reason:             "ConvergeFailure",
				Message:            "ResourceExport can't be converged to ResourceImport",
			},
		}
	}

	resExport.Status = mcsv1alpha1.ResourceExportStatus{
		Conditions: newConditions,
	}
	err := r.Client.Status().Update(context.Background(), resExport)
	if err != nil {
		klog.ErrorS(err, "Failed to update ResourceExport status", "resourceexport", klog.KObj(resExport))
	}
}

// deleteResourceExport removes ResourceExport finalizer string and updates it, so Kubernetes can complete deletion.
func (r *ResourceExportReconciler) deleteResourceExport(resExport *mcsv1alpha1.ResourceExport) (ctrl.Result, error) {
	resExport.SetFinalizers(common.RemoveStringFromSlice(resExport.Finalizers, constants.ResourceExportFinalizer))
	if err := r.Client.Update(context.Background(), resExport, &client.UpdateOptions{}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ResourceExportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Ignore status update event via GenerationChangedPredicate
	generationPredicate := predicate.GenerationChangedPredicate{}
	// Register this controller to ignore LabelIdentity kind of ResourceExport
	labelIdentityResExportFilter := func(object client.Object) bool {
		if resExport, ok := object.(*mcsv1alpha1.ResourceExport); ok {
			return resExport.Spec.Kind != constants.LabelIdentityKind
		}
		return false
	}
	labelIdentityResExportPredicate := predicate.NewPredicateFuncs(labelIdentityResExportFilter)
	instance := predicate.And(generationPredicate, labelIdentityResExportPredicate)
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
			constants.SourceNamespace: resExport.Spec.Namespace,
			constants.SourceName:      resExport.Spec.Name,
			constants.SourceKind:      resExport.Spec.Kind,
		},
	}
	selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
	return selector
}

func SvcPortsConverter(svcPort []corev1.ServicePort) []mcs.ServicePort {
	var mcsSP []mcs.ServicePort
	for _, v := range svcPort {
		mcsSP = append(mcsSP, mcs.ServicePort{
			Name:     v.Name,
			Port:     v.Port,
			Protocol: v.Protocol,
		})
	}
	return mcsSP
}

func GetResourceImportName(resExport *mcsv1alpha1.ResourceExport) types.NamespacedName {
	if resExport.Spec.Namespace != "" {
		return types.NamespacedName{
			Namespace: resExport.Namespace,
			Name:      resExport.Spec.Namespace + "-" + resExport.Spec.Name + "-" + strings.ToLower(resExport.Spec.Kind),
		}
	}
	return types.NamespacedName{
		Namespace: resExport.Namespace,
		Name:      resExport.Spec.Name + "-" + strings.ToLower(resExport.Spec.Kind),
	}
}

// We use finalizers as ResourceExport pre-delete hooks, which means when
// we list the ResourceExports, it will also return deleted items.
// RemoveDeletedResourceExports remove any ResourceExports with non-zero DeletionTimestamp
// which is actually deleted object.
func RemoveDeletedResourceExports(items []mcsv1alpha1.ResourceExport) []mcsv1alpha1.ResourceExport {
	var undeleteItems []mcsv1alpha1.ResourceExport
	for _, i := range items {
		if i.DeletionTimestamp.IsZero() {
			undeleteItems = append(undeleteItems, i)
		}
	}
	return undeleteItems
}
