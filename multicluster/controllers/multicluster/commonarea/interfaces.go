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

package commonarea

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

// CommonArea is an interface that provides access to the Common Area of a ClusterSet.
// Common Area of a ClusterSet is a Namespace in the leader cluster.
type CommonArea interface {
	// Client grants read/write to the Namespace of the cluster that is backing this CommonArea.
	client.Client

	// GetClusterID returns the clusterID of the leader cluster.
	GetClusterID() common.ClusterID

	// GetNamespace returns the Namespace backing this CommonArea.
	GetNamespace() string
}

// RemoteCommonArea is an abstraction to connect to CommonArea of the leader cluster.
type RemoteCommonArea interface {
	CommonArea

	Start() context.CancelFunc

	Stop()

	// IsConnected returns whether the RemoteCommonArea is accessible or not.
	IsConnected() bool

	// StartWatching sets up a Manager to reconcile resource CRUD operations from CommonArea of RemoteCommonArea.
	StartWatching() error

	// StopWatching stops the Manager so the crud operations in RemoteCommonArea no longer invoke the reconcilers.
	StopWatching()

	GetStatus() []v1alpha2.ClusterCondition

	GetLocalClusterID() string

	// AddImportReconciler adds an ImportReconciler to be started with StartWatching().
	AddImportReconciler(reconciler ImportReconciler)
}

// ImportReconciler is an abstraction for member cluster controllers that reconciles ResourceImports
// in a RemoteCommonArea.
type ImportReconciler interface {
	// SetupWithManager can be called multiple times when StartWatching() fails and is called more
	// than once.
	SetupWithManager(mgr ctrl.Manager) error
}

type RemoteCommonAreaGetter interface {
	GetRemoteCommonAreaAndLocalID() (RemoteCommonArea, string, error)
}
