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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	LeaderCluster = "leader"
	MemberCluster = "member"

	memberClusterAnnounceStaleTime = 5 * time.Minute
)

// StaleResCleanupController will clean up ServiceImport, MC Service, ACNP, ClusterInfoImport and LabelIdentity
// resources if no corresponding ResourceImports in the leader cluster and remove stale ResourceExports
// in the leader cluster if no corresponding ServiceExport or Gateway in the member cluster when it runs in
// the member cluster.
// It will clean up stale MemberClusterAnnounce resources in the leader cluster if no corresponding member
// cluster in the ClusterSet.Spec.Members when it runs in the leader cluster.
type StaleResCleanupController struct {
	client.Client
	Scheme           *runtime.Scheme
	localClusterID   string
	commonAreaGetter commonarea.RemoteCommonAreaGetter
	namespace        string
	clusterRole      string
	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
}

func NewStaleResCleanupController(
	Client client.Client,
	Scheme *runtime.Scheme,
	namespace string,
	commonAreaGetter commonarea.RemoteCommonAreaGetter,
	clusterRole string,
) *StaleResCleanupController {
	reconciler := &StaleResCleanupController{
		Client:           Client,
		Scheme:           Scheme,
		namespace:        namespace,
		commonAreaGetter: commonAreaGetter,
		clusterRole:      clusterRole,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "StaleResCleanupController"),
	}
	return reconciler
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=multicluster.x-k8s.io,resources=serviceimports,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceimports,verbs=get;list;watch;
// +kubebuilder:rbac:groups=multicluster.crd.antrea.io,resources=resourceexports,verbs=get;list;watch;delete

func (c *StaleResCleanupController) cleanup() error {
	switch c.clusterRole {
	case LeaderCluster:
		return c.cleanupStaleResourcesOnLeader()
	case MemberCluster:
		return c.cleanupStaleResourcesOnMember()
	}
	return nil
}

func (c *StaleResCleanupController) cleanupStaleResourcesOnLeader() error {
	return c.cleanupMemberClusterAnnounces()
}

func (c *StaleResCleanupController) cleanupStaleResourcesOnMember() error {
	var err error
	var commonArea commonarea.RemoteCommonArea
	commonArea, c.localClusterID, err = c.commonAreaGetter.GetRemoteCommonAreaAndLocalID()
	if err != nil {
		return err
	}

	resImpList := &mcsv1alpha1.ResourceImportList{}
	if err := commonArea.List(context.Background(), resImpList, &client.ListOptions{Namespace: commonArea.GetNamespace()}); err != nil {
		return err
	}
	if err := c.cleanupStaleServiceResources(commonArea, resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale imported Services")
		return err
	}
	// Cleanup any imported ACNPs that do not have corresponding ResourceImport anymore
	if err := c.cleanupACNPResources(resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale imported ACNPs")
		return err
	}
	if err := c.cleanupClusterInfoImport(resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale ClusterInfoImports")
		return err
	}
	if err := c.cleanupLabelIdentities(resImpList); err != nil {
		klog.ErrorS(err, "Failed to cleanup stale imported LabelIdentities")
		return err
	}

	// Clean up stale ResourceExports in the leader cluster.
	resExpList := &mcsv1alpha1.ResourceExportList{}
	if err := commonArea.List(context.Background(), resExpList, &client.ListOptions{Namespace: commonArea.GetNamespace()}); err != nil {
		return err
	}

	if len(resExpList.Items) == 0 {
		return nil
	}
	if err := c.cleanupServiceResourceExport(commonArea, resExpList); err != nil {
		return err
	}
	if err := c.cleanupClusterInfoResourceExport(commonArea, resExpList); err != nil {
		return err
	}
	if err := c.cleanupLabelIdentityResourceExport(commonArea, resExpList); err != nil {
		return err
	}
	return nil
}

func (c *StaleResCleanupController) cleanupStaleServiceResources(commonArea commonarea.RemoteCommonArea,
	resImpList *mcsv1alpha1.ResourceImportList) error {
	svcImpList := &k8smcsv1alpha1.ServiceImportList{}
	if err := c.List(context.Background(), svcImpList, &client.ListOptions{}); err != nil {
		return err
	}

	svcList := &corev1.ServiceList{}
	if err := c.List(context.Background(), svcList, &client.ListOptions{}); err != nil {
		return err
	}

	svcImpItems := map[string]k8smcsv1alpha1.ServiceImport{}
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
		if err := c.Client.Delete(context.Background(), &svc, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	for _, staleSvcImp := range svcImpItems {
		svcImp := staleSvcImp
		klog.InfoS("Cleaning up stale ServiceImport", "serviceimport", klog.KObj(&svcImp))
		if err := c.Client.Delete(context.Background(), &svcImp, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanupACNPResources(resImpList *mcsv1alpha1.ResourceImportList) error {
	acnpList := &crdv1alpha1.ClusterNetworkPolicyList{}
	if err := c.List(context.Background(), acnpList, &client.ListOptions{}); err != nil {
		return err
	}
	staleMCACNPItems := map[string]crdv1alpha1.ClusterNetworkPolicy{}
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
		if err := c.Client.Delete(context.Background(), &acnp, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanupClusterInfoImport(resImpList *mcsv1alpha1.ResourceImportList) error {
	ciImpList := &mcsv1alpha1.ClusterInfoImportList{}
	if err := c.List(context.Background(), ciImpList, &client.ListOptions{}); err != nil {
		return err
	}

	staleCIImps := map[string]mcsv1alpha1.ClusterInfoImport{}
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
		if err := c.Client.Delete(context.Background(), &ciImp, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanupLabelIdentities(resImpList *mcsv1alpha1.ResourceImportList) error {
	labelIdentityList := &mcsv1alpha1.LabelIdentityList{}
	if err := c.List(context.Background(), labelIdentityList, &client.ListOptions{}); err != nil {
		return err
	}
	staleLabelIdentities := map[string]mcsv1alpha1.LabelIdentity{}
	for _, labelIdentityObj := range labelIdentityList.Items {
		staleLabelIdentities[labelIdentityObj.Name] = labelIdentityObj
	}
	for _, labelImp := range resImpList.Items {
		delete(staleLabelIdentities, labelImp.Name)
	}
	for _, l := range staleLabelIdentities {
		labelIdentity := l
		klog.V(2).InfoS("Cleaning up stale imported LabelIdentity", "labelidentity", klog.KObj(&labelIdentity))
		if err := c.Client.Delete(context.Background(), &labelIdentity, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// cleanupServiceResourceExport removes any Service/Endpoint kind of ResourceExports when there is no
// corresponding ServiceExport in the local cluster.
func (c *StaleResCleanupController) cleanupServiceResourceExport(commonArea commonarea.RemoteCommonArea,
	resExpList *mcsv1alpha1.ResourceExportList) error {
	svcExpList := &k8smcsv1alpha1.ServiceExportList{}
	if err := c.List(context.Background(), svcExpList, &client.ListOptions{}); err != nil {
		return err
	}
	allResExpItems := resExpList.Items
	svcExpItems := svcExpList.Items
	staleResExpItems := map[string]mcsv1alpha1.ResourceExport{}

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
		if err := commonArea.Delete(context.Background(), &re, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanupLabelIdentityResourceExport(commonArea commonarea.RemoteCommonArea,
	resExpList *mcsv1alpha1.ResourceExportList) error {
	podList, nsList := &corev1.PodList{}, &corev1.NamespaceList{}
	if err := c.List(context.Background(), podList, &client.ListOptions{}); err != nil {
		return err
	}
	if err := c.List(context.Background(), nsList, &client.ListOptions{}); err != nil {
		return err
	}
	allResExpItems := resExpList.Items
	staleResExpItems := map[string]mcsv1alpha1.ResourceExport{}
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
		normalizedLabel := podNSlabel + "&pod:" + labels.FormatLabels(p.Labels)
		delete(staleResExpItems, normalizedLabel)
	}
	for _, r := range staleResExpItems {
		re := r
		klog.InfoS("Cleaning up stale ResourceExport", "ResourceExport", klog.KObj(&re))
		if err := commonArea.Delete(context.Background(), &re, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// cleanupClusterInfoResourceExport removes any ClusterInfo kind of ResourceExports when there is no
// Gateway in the local cluster.
func (c *StaleResCleanupController) cleanupClusterInfoResourceExport(commonArea commonarea.RemoteCommonArea,
	resExpList *mcsv1alpha1.ResourceExportList) error {
	var gws mcsv1alpha1.GatewayList
	if err := c.Client.List(context.Background(), &gws, &client.ListOptions{}); err != nil {
		return err
	}

	if len(gws.Items) == 0 {
		ciExport := &mcsv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: commonArea.GetNamespace(),
				Name:      common.NewClusterInfoResourceExportName(c.localClusterID),
			},
		}
		klog.InfoS("Cleaning up stale ClusterInfo kind of ResourceExport", "resourceexport", klog.KObj(ciExport))
		if err := commonArea.Delete(context.Background(), ciExport, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *StaleResCleanupController) cleanupMemberClusterAnnounces() error {
	memberClusterAnnounceList := &mcsv1alpha1.MemberClusterAnnounceList{}
	if err := c.List(context.Background(), memberClusterAnnounceList, &client.ListOptions{}); err != nil {
		return err
	}

	for _, m := range memberClusterAnnounceList.Items {
		memberClusterAnnounce := m
		lastUpdateTime, err := time.Parse(time.RFC3339, memberClusterAnnounce.Annotations[commonarea.TimestampAnnotationKey])
		if err == nil && time.Now().Sub(lastUpdateTime) < memberClusterAnnounceStaleTime {
			continue
		}
		if err == nil {
			klog.InfoS("Cleaning up stale MemberClusterAnnounce. It has not been updated within the agreed period", "MemberClusterAnnounce", klog.KObj(&memberClusterAnnounce), "agreedPeriod", memberClusterAnnounceStaleTime)
		} else {
			klog.InfoS("Cleaning up stale MemberClusterAnnounce. The latest update time is not in RFC3339 format", "MemberClusterAnnounce", klog.KObj(&memberClusterAnnounce))
		}

		if err := c.Client.Delete(context.Background(), &memberClusterAnnounce, &client.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to delete stale MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(&memberClusterAnnounce))
			return err
		}
	}
	return nil
}

// Enqueue will be called after StaleResCleanupController is initialized.
func (c *StaleResCleanupController) Enqueue() {
	// The key can be anything as we only have single item.
	c.queue.Add("key")
}

// Run starts the StaleResCleanupController and blocks until stopCh is closed.
// it will run only once to clean up stale resources if no error happens.
func (c *StaleResCleanupController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting StaleResCleanupController")
	defer klog.InfoS("Shutting down StaleResCleanupController")

	if err := c.RunOnce(); err != nil {
		c.Enqueue()
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *StaleResCleanupController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *StaleResCleanupController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.cleanup()
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	klog.ErrorS(err, "Error removing stale resources, requeuing it")
	c.queue.AddRateLimited(key)
	return true
}

func (c *StaleResCleanupController) RunOnce() error {
	err := c.cleanup()
	if err != nil {
		return err
	}
	return nil
}

// Test for codecov
