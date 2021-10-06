package internal

import (
	"context"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

/**
 *  This file contains implementation to manage access to common area in the local cluster backed by a namespace
 */

type LocalClusterManager interface {
	// Access to write into the common area of the local cluster
	// Access to read is likely not needed as the reconciler already is setup to notify changes
	common.CommonArea

	// Start the local cluster manager and block on a go routine
	Start() error

	// cleanup any state and Stop the local cluster manager
	Stop() error
}

type localClusterManager struct {
	client.Client

	log logr.Logger
	// this is the local cluster ID
	clusterID common.ClusterID
	// namespace for the cluster manager to operate in, same as the
	// namespace in which the cluster set is defined
	namespace string
	// Function to stop this manager
	stopFunc context.CancelFunc
}

func NewLocalClusterManager(client client.Client, clusterID common.ClusterID, namespace string, log logr.Logger) LocalClusterManager {
	return &localClusterManager{
		Client:    client,
		log:       log.WithName("LocalClusterManager"),
		clusterID: clusterID,
		namespace: namespace,
	}
}

/**
 *  LocalClusterManager implementation
 */

func (i *localClusterManager) Start() error {
	stopCtx, stopFunc := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case <-stopCtx.Done():
				return
			}
		}
	}()

	i.stopFunc = stopFunc
	return nil
}

func (i *localClusterManager) Stop() error {
	if i.stopFunc != nil {
		i.stopFunc()
	}
	return nil
}

/**
 *  CommonArea implementation
 */

// GetClusterID returns the clusterID of the cluster accessed by this common area
func (i *localClusterManager) GetClusterID() common.ClusterID {
	return i.clusterID
}

// Get namespace backing this common area
func (i *localClusterManager) GetNamespace() string {
	return i.namespace
}
