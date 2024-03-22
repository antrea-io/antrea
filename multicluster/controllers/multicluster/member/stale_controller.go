/*
Copyright 2023 Antrea Authors.

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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8smcv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

// StaleResCleanupController will clean up ServiceImport, MC Service, ACNP, ClusterInfoImport and LabelIdentity
// resources if no corresponding ResourceImports in the leader cluster and remove stale ResourceExports
// in the leader cluster if no corresponding ServiceExport or Gateway in the member cluster when it runs in
// the member cluster. StaleResCleanupController one-time runner will run only once in the member cluster
// during Multi-cluster Controller starts, and it will retry only if there is an error.
// StaleResCleanupController's reconciler will handle ClusterSet deletion event to clean up all
// automatically created resources for the ClusterSet.
type StaleResCleanupController struct {
	client.Client
	Scheme               *runtime.Scheme
	commonAreaCreationCh chan struct{}
	localClusterID       string
	commonAreaGetter     commonarea.RemoteCommonAreaGetter
	namespace            string
}

func NewStaleResCleanupController(
	Client client.Client,
	Scheme *runtime.Scheme,
	commonAreaCreationCh chan struct{},
	namespace string,
	commonAreaGetter commonarea.RemoteCommonAreaGetter,
) *StaleResCleanupController {
	reconciler := &StaleResCleanupController{
		Client:               Client,
		Scheme:               Scheme,
		commonAreaCreationCh: commonAreaCreationCh,
		namespace:            namespace,
		commonAreaGetter:     commonAreaGetter,
	}
	return reconciler
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceimports,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports,verbs=get;list;watch;
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;delete

func (c *StaleResCleanupController) CleanUp(ctx context.Context) error {
	var err error
	clusterSets := &mcv1alpha2.ClusterSetList{}
	if err = c.Client.List(ctx, clusterSets, &client.ListOptions{}); err != nil {
		return err
	}

	if len(clusterSets.Items) == 0 {
		klog.InfoS("There is no existing ClusterSet, try to clean up all auto-generated resources by Antrea Multi-cluster")
		if err = cleanUpResourcesCreatedByMC(ctx, c.Client); err != nil {
			return err
		}
	}

	return nil
}

func (c *StaleResCleanupController) cleanUpStaleResourcesOnMember(ctx context.Context, commonArea commonarea.RemoteCommonArea) error {
	svcImpList := &k8smcv1alpha1.ServiceImportList{}
	if err := c.List(ctx, svcImpList, &client.ListOptions{}); err != nil {
		return err
	}
	svcList := &corev1.ServiceList{}
	if err := c.List(ctx, svcList, &client.ListOptions{}); err != nil {
		return err
	}
	acnpList := &crdv1beta1.ClusterNetworkPolicyList{}
	if err := c.List(ctx, acnpList, &client.ListOptions{}); err != nil {
		return err
	}
	ciImpList := &mcv1alpha1.ClusterInfoImportList{}
	if err := c.List(ctx, ciImpList, &client.ListOptions{}); err != nil {
		return err
	}
	labelIdentityList := &mcv1alpha1.LabelIdentityList{}
	if err := c.List(ctx, labelIdentityList, &client.ListOptions{}); err != nil {
		return err
	}
	// All previously imported resources need to be listed before ResourceImports are listed.
	// This prevents race condition between stale_controller and other reconcilers.
	// See https://github.com/antrea-io/antrea/issues/4854
	resImpList := &mcv1alpha1.ResourceImportList{}
	if err := commonArea.List(ctx, resImpList, &client.ListOptions{Namespace: commonArea.GetNamespace()}); err != nil {
		return err
	}
	// Clean up any imported Services that do not have corresponding ResourceImport anymore
	if err := c.cleanUpStaleServiceResources(ctx, svcImpList, svcList, resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale imported Services")
		return err
	}
	// Clean up any imported ACNPs that do not have corresponding ResourceImport anymore
	if err := c.cleanUpACNPResources(ctx, acnpList, resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale imported ACNPs")
		return err
	}
	// Clean up any imported ClusterInfos that do not have corresponding ResourceImport anymore
	if err := c.cleanUpClusterInfoImports(ctx, ciImpList, resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale ClusterInfoImports")
		return err
	}
	// Clean up any imported LabelIdentities that do not have corresponding ResourceImport anymore
	if err := c.cleanUpLabelIdentities(ctx, labelIdentityList, resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale imported LabelIdentities")
		return err
	}
	return nil
}

// Clean up stale ResourceExports in the leader cluster for a member cluster.
func (c *StaleResCleanupController) cleanUpStaleResourceExportsOnLeader(ctx context.Context, commonArea commonarea.RemoteCommonArea) error {
	if err := c.cleanUpClusterInfoResourceExports(ctx, commonArea); err != nil {
		return err
	}
	resExpList := &mcv1alpha1.ResourceExportList{}
	if err := commonArea.List(ctx, resExpList, &client.ListOptions{Namespace: commonArea.GetNamespace()}); err != nil {
		return err
	}
	if len(resExpList.Items) == 0 {
		return nil
	}
	if err := c.cleanUpServiceResourceExports(ctx, commonArea, resExpList); err != nil {
		return err
	}
	if err := c.cleanUpLabelIdentityResourceExports(ctx, commonArea, resExpList); err != nil {
		return err
	}
	return nil
}

func (c *StaleResCleanupController) cleanUpStaleServiceResources(ctx context.Context, svcImpList *k8smcv1alpha1.ServiceImportList,
	svcList *corev1.ServiceList, resImpList *mcv1alpha1.ResourceImportList) error {
	svcImpItems := map[string]k8smcv1alpha1.ServiceImport{}
	for _, svcImp := range svcImpList.Items {
		svcImpItems[svcImp.Namespace+"/"+svcImp.Name] = svcImp
	}

	mcsSvcItems := map[string]corev1.Service{}
	for _, svc := range svcList.Items {
		if _, ok := svc.Annotations[common.AntreaMCServiceAnnotation]; ok {
			mcsSvcItems[svc.Namespace+"/"+svc.Name] = svc
		}
	}
	for _, resImp := range resImpList.Items {
		if resImp.Spec.Kind == constants.ServiceImportKind {
			delete(mcsSvcItems, resImp.Spec.Namespace+"/"+common.AntreaMCSPrefix+resImp.Spec.Name)
			delete(svcImpItems, resImp.Spec.Namespace+"/"+resImp.Spec.Name)
		}
	}

	for _, staleSvc := range mcsSvcItems {
		svc := staleSvc
		klog.InfoS("Cleaning up stale imported Service", "service", klog.KObj(&svc))
		if err := c.Client.Delete(ctx, &svc, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	for _, staleSvcImp := range svcImpItems {
		svcImp := staleSvcImp
		klog.InfoS("Cleaning up stale ServiceImport", "serviceimport", klog.KObj(&svcImp))
		if err := c.Client.Delete(ctx, &svcImp, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanUpACNPResources(ctx context.Context, acnpList *crdv1beta1.ClusterNetworkPolicyList,
	resImpList *mcv1alpha1.ResourceImportList) error {
	staleMCACNPItems := map[string]crdv1beta1.ClusterNetworkPolicy{}
	for _, acnp := range acnpList.Items {
		if _, ok := acnp.Annotations[common.AntreaMCACNPAnnotation]; ok {
			staleMCACNPItems[acnp.Name] = acnp
		}
	}
	for _, resImp := range resImpList.Items {
		if resImp.Spec.Kind == constants.AntreaClusterNetworkPolicyKind {
			acnpNameFromResImp := common.AntreaMCSPrefix + resImp.Spec.Name
			delete(staleMCACNPItems, acnpNameFromResImp)
		}
	}
	for _, stalePolicy := range staleMCACNPItems {
		acnp := stalePolicy
		klog.InfoS("Cleaning up stale imported ACNP", "acnp", klog.KObj(&acnp))
		if err := c.Client.Delete(ctx, &acnp, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanUpClusterInfoImports(ctx context.Context, ciImpList *mcv1alpha1.ClusterInfoImportList,
	resImpList *mcv1alpha1.ResourceImportList) error {
	staleCIImps := map[string]mcv1alpha1.ClusterInfoImport{}
	for _, item := range ciImpList.Items {
		staleCIImps[item.Name] = item
	}
	for _, resImp := range resImpList.Items {
		if resImp.Spec.Kind == constants.ClusterInfoKind {
			delete(staleCIImps, resImp.Name)
		}
	}
	for _, staleCIImp := range staleCIImps {
		ciImp := staleCIImp
		klog.InfoS("Cleaning up stale ClusterInfoImport", "clusterinfoimport", klog.KObj(&ciImp))
		if err := c.Client.Delete(ctx, &ciImp, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanUpLabelIdentities(ctx context.Context, labelIdentityList *mcv1alpha1.LabelIdentityList,
	resImpList *mcv1alpha1.ResourceImportList) error {
	staleLabelIdentities := map[string]mcv1alpha1.LabelIdentity{}
	for _, labelIdentityObj := range labelIdentityList.Items {
		staleLabelIdentities[labelIdentityObj.Name] = labelIdentityObj
	}
	for _, labelImp := range resImpList.Items {
		delete(staleLabelIdentities, labelImp.Name)
	}
	for _, l := range staleLabelIdentities {
		labelIdentity := l
		klog.V(2).InfoS("Cleaning up stale imported LabelIdentity", "labelidentity", klog.KObj(&labelIdentity))
		if err := c.Client.Delete(ctx, &labelIdentity, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// cleanUpServiceResourceExports removes any Service/Endpoint kind of ResourceExports when there is no
// corresponding ServiceExport in the local cluster.
func (c *StaleResCleanupController) cleanUpServiceResourceExports(ctx context.Context, commonArea commonarea.RemoteCommonArea, resExpList *mcv1alpha1.ResourceExportList) error {
	svcExpList := &k8smcv1alpha1.ServiceExportList{}
	if err := c.List(ctx, svcExpList, &client.ListOptions{}); err != nil {
		return err
	}
	allResExpItems := resExpList.Items
	svcExpItems := svcExpList.Items
	staleResExpItems := map[string]mcv1alpha1.ResourceExport{}

	for _, resExp := range allResExpItems {
		if resExp.Spec.Kind == constants.ServiceKind && resExp.Labels[constants.SourceClusterID] == c.localClusterID {
			staleResExpItems[resExp.Spec.Namespace+"/"+resExp.Spec.Name+"service"] = resExp
		}
		if resExp.Spec.Kind == constants.EndpointsKind && resExp.Labels[constants.SourceClusterID] == c.localClusterID {
			staleResExpItems[resExp.Spec.Namespace+"/"+resExp.Spec.Name+"endpoint"] = resExp
		}
	}

	for _, se := range svcExpItems {
		delete(staleResExpItems, se.Namespace+"/"+se.Name+"service")
		delete(staleResExpItems, se.Namespace+"/"+se.Name+"endpoint")
	}

	for _, r := range staleResExpItems {
		re := r
		klog.InfoS("Cleaning up stale ResourceExport", "ResourceExport", klog.KObj(&re))
		if err := commonArea.Delete(ctx, &re, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanUpLabelIdentityResourceExports(ctx context.Context, commonArea commonarea.RemoteCommonArea, resExpList *mcv1alpha1.ResourceExportList) error {
	podList, nsList := &corev1.PodList{}, &corev1.NamespaceList{}
	if err := c.List(ctx, podList, &client.ListOptions{}); err != nil {
		return err
	}
	if err := c.List(ctx, nsList, &client.ListOptions{}); err != nil {
		return err
	}
	allResExpItems := resExpList.Items
	staleResExpItems := map[string]mcv1alpha1.ResourceExport{}
	for _, resExp := range allResExpItems {
		if resExp.Spec.Kind == constants.LabelIdentityKind && resExp.Labels[constants.SourceClusterID] == c.localClusterID {
			staleResExpItems[resExp.Spec.LabelIdentity.NormalizedLabel] = resExp
		}
	}
	nsLabelMap := map[string]string{}
	for _, ns := range nsList.Items {
		if _, ok := ns.Labels[corev1.LabelMetadataName]; !ok {
			// NamespaceDefaultLabelName is supported from K8s v1.21. For K8s versions before v1.21,
			// we append the Namespace name label to the Namespace label set.
			ns.Labels[corev1.LabelMetadataName] = ns.Name
		}
		nsLabelMap[ns.Name] = "ns:" + labels.FormatLabels(ns.Labels)
	}
	for _, p := range podList.Items {
		podNSlabel, ok := nsLabelMap[p.Namespace]
		if !ok {
			continue
		}
		normalizedLabel := podNSlabel + "&pod:" + labels.Set(p.Labels).String()
		delete(staleResExpItems, normalizedLabel)
	}
	for _, r := range staleResExpItems {
		re := r
		klog.InfoS("Cleaning up stale ResourceExport", "ResourceExport", klog.KObj(&re))
		if err := commonArea.Delete(ctx, &re, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// cleanUpClusterInfoResourceExports removes any ClusterInfo kind of ResourceExports when there is no
// Gateway in the local cluster.
func (c *StaleResCleanupController) cleanUpClusterInfoResourceExports(ctx context.Context, commonArea commonarea.RemoteCommonArea) error {
	var gws mcv1alpha1.GatewayList
	if err := c.Client.List(ctx, &gws, &client.ListOptions{}); err != nil {
		return err
	}

	if len(gws.Items) == 0 {
		ciExport := &mcv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: commonArea.GetNamespace(),
				Name:      common.NewClusterInfoResourceExportName(c.localClusterID),
			},
		}
		klog.InfoS("Cleaning up stale ClusterInfo kind of ResourceExport", "resourceexport", klog.KObj(ciExport))
		if err := commonArea.Delete(ctx, ciExport, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// Run starts the StaleResCleanupController and blocks until stopCh is closed.
func (c *StaleResCleanupController) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting StaleResCleanupController")
	defer klog.InfoS("Shutting down StaleResCleanupController")

	ctx := wait.ContextForChannel(stopCh)

	go func() {
		retry.OnError(common.CleanUpRetry, func(err error) bool { return true },
			func() error {
				return c.CleanUp(ctx)
			})
	}()

	for range c.commonAreaCreationCh {
		retry.OnError(common.CleanUpRetry, func(err error) bool { return true },
			func() error {
				if err := c.cleanUpStaleResources(ctx); err != nil {
					klog.ErrorS(err, "Failed to clean up stale resources after a ClusterSet is created, will retry later")
					return err
				}
				return nil
			})
	}
}

func (c *StaleResCleanupController) cleanUpStaleResources(ctx context.Context) error {
	var err error
	var commonArea commonarea.RemoteCommonArea
	commonArea, c.localClusterID, err = c.commonAreaGetter.GetRemoteCommonAreaAndLocalID()
	if err != nil {
		return err
	}

	klog.InfoS("Clean up all stale imported and exported resources created by Antrea Multi-cluster Controller")
	if err = c.cleanUpStaleResourcesOnMember(ctx, commonArea); err != nil {
		return err
	}
	// Clean up stale ResourceExports in the leader cluster for a member cluster.
	if err := c.cleanUpStaleResourceExportsOnLeader(ctx, commonArea); err != nil {
		return err
	}
	return nil
}

func cleanUpResourcesCreatedByMC(ctx context.Context, mgrClient client.Client) error {
	var err error
	if err = cleanUpMCServicesAndServiceImports(ctx, mgrClient); err != nil {
		return err
	}
	if err = cleanUpReplicatedACNPs(ctx, mgrClient); err != nil {
		return err
	}
	if err = cleanUpLabelIdentities(ctx, mgrClient); err != nil {
		return err
	}
	if err = cleanUpClusterInfoImports(ctx, mgrClient); err != nil {
		return err
	}
	if err = cleanUpGateways(ctx, mgrClient); err != nil {
		return err
	}
	return nil
}

func cleanUpMCServicesAndServiceImports(ctx context.Context, mgrClient client.Client) error {
	svcImpList := &k8smcv1alpha1.ServiceImportList{}
	err := mgrClient.List(ctx, svcImpList, &client.ListOptions{})
	if err != nil {
		return err
	}
	for _, svcImp := range svcImpList.Items {
		svcImpTmp := svcImp
		mcsvc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: svcImp.Namespace,
				Name:      common.ToMCResourceName(svcImp.Name),
			},
		}
		err = mgrClient.Delete(ctx, mcsvc, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		err = mgrClient.Delete(ctx, &svcImpTmp, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func cleanUpReplicatedACNPs(ctx context.Context, mgrClient client.Client) error {
	acnpList := &crdv1beta1.ClusterNetworkPolicyList{}
	if err := mgrClient.List(ctx, acnpList, &client.ListOptions{}); err != nil {
		return err
	}
	for _, acnp := range acnpList.Items {
		acnpTmp := acnp
		if metav1.HasAnnotation(acnp.ObjectMeta, common.AntreaMCACNPAnnotation) {
			err := mgrClient.Delete(ctx, &acnpTmp, &client.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func cleanUpLabelIdentities(ctx context.Context, mgrClient client.Client) error {
	labelIdentityList := &mcv1alpha1.LabelIdentityList{}
	if err := mgrClient.List(ctx, labelIdentityList, &client.ListOptions{}); err != nil {
		return err
	}
	for _, labelIdt := range labelIdentityList.Items {
		labelIdtTmp := labelIdt
		err := mgrClient.Delete(ctx, &labelIdtTmp, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func cleanUpClusterInfoImports(ctx context.Context, mgrClient client.Client) error {
	ciImpList := &mcv1alpha1.ClusterInfoImportList{}
	if err := mgrClient.List(ctx, ciImpList, &client.ListOptions{}); err != nil {
		return err
	}
	for _, ciImp := range ciImpList.Items {
		ciImpTmp := ciImp
		err := mgrClient.Delete(ctx, &ciImpTmp, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func cleanUpGateways(ctx context.Context, mgrClient client.Client) error {
	gwList := &mcv1alpha1.GatewayList{}
	if err := mgrClient.List(ctx, gwList, &client.ListOptions{}); err != nil {
		return err
	}
	for _, gw := range gwList.Items {
		gwTmp := gw
		err := mgrClient.Delete(ctx, &gwTmp, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
