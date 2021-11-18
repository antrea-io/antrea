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

package common

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CommonArea is an interface that provides access to the common area of a ClusterSet.
// Common Area of a ClusterSet is a Namespace in the leader cluster.
type CommonArea interface {
	// Client grants read/write to the namespace of the cluster that is backing this CommonArea.
	client.Client

	// GetClusterID returns the clusterID of the cluster accessed by this CommonArea.
	GetClusterID() ClusterID

	// GetNamespace returns the Namespace backing this CommonArea.
	GetNamespace() string
}
