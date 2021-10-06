package common

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Access to common area of a cluster
// For common area used in LocalClusterManager - this provides access to the local cluster in a given namespace
// for common area used in RemoteCluster - this provides access to the remote cluster's namespace
type CommonArea interface {
	// Grant read/write to the cluster for a specific namespace
	client.Client

	// GetClusterID returns the clusterID of the cluster accessed by this common area
	GetClusterID() ClusterID

	// Get namespace backing this common area
	GetNamespace() string
}
