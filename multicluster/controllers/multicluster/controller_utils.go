package multicluster

import (
	"context"
	"fmt"

	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

func validateLocalClusterClaim(c client.Client, clusterSet *multiclusterv1alpha1.ClusterSet) (clusterId common.ClusterID, clusterSetId common.ClusterSetID, err error) {
	configNamespace := clusterSet.GetNamespace()

	clusterClaimList := &multiclusterv1alpha1.ClusterClaimList{}
	klog.InfoS("Validating cluster claim in", "Namespace", configNamespace)
	if err = c.List(context.TODO(), clusterClaimList, client.InNamespace(configNamespace)); err != nil {
		return
	}
	if len(clusterClaimList.Items) == 0 {
		err = fmt.Errorf("ClusterClaim is not configured for the cluster")
		return
	}

	wellKnownClusterSetClaimIDExist := false
	wellKnownClusterClaimIDExist := false
	for _, clusterClaim := range clusterClaimList.Items {
		klog.InfoS("Processing ClusterClaim", "Name", clusterClaim.Name, "Value", clusterClaim.Value)
		if clusterClaim.Name == multiclusterv1alpha1.WellKnownClusterClaimClusterSet {
			wellKnownClusterSetClaimIDExist = true
			clusterSetId = common.ClusterSetID(clusterClaim.Value)
		} else if clusterClaim.Name == multiclusterv1alpha1.WellKnownClusterClaimID {
			wellKnownClusterClaimIDExist = true
			clusterId = common.ClusterID(clusterClaim.Value)
		}
	}

	if !wellKnownClusterSetClaimIDExist {
		err = fmt.Errorf("ClusterClaim not configured for Name=%s",
			multiclusterv1alpha1.WellKnownClusterClaimClusterSet)
		return
	}

	if !wellKnownClusterClaimIDExist {
		err = fmt.Errorf("ClusterClaim not configured for Name=%s",
			multiclusterv1alpha1.WellKnownClusterClaimID)
		return
	}

	if clusterSet.Name != string(clusterSetId) {
		err = fmt.Errorf("ClusterSet Name=%s is not same as ClusterClaim Value=%s for Name=%s",
			clusterSet.Name, clusterSetId, multiclusterv1alpha1.WellKnownClusterClaimClusterSet)
		return
	}

	return
}

func validateConfigExists(clusterId common.ClusterID, clusters []multiclusterv1alpha1.MemberCluster) (err error) {
	configExists := false
	for _, cluster := range clusters {
		if string(clusterId) == cluster.ClusterID {
			configExists = true
			break
		}
	}
	if !configExists {
		err = fmt.Errorf("validating cluster %s exists in %v failed", clusterId, clusters)
		return
	}
	return
}

func validateClusterSetNamespace(clusterSet *multiclusterv1alpha1.ClusterSet) (err error) {
	//  validate the Namespace is the same
	if clusterSet.Spec.Namespace != clusterSet.GetNamespace() {
		err = fmt.Errorf("ClusterSet Namespace %s is different from %s",
			clusterSet.Spec.Namespace, clusterSet.GetNamespace())
		return
	}
	return
}
