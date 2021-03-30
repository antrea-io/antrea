// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clusteridentity

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

const (
	DefaultClusterIdentityConfigMapName = "antrea-cluster-identity"
	uuidConfigMapKey                    = "uuid"
)

// ClusterIdentityAllocator ensures that the antrea-cluster-identity ConfigMap is populated
// correctly, with a valid UUID. It is meant to be used by the Antrea Controller.
type ClusterIdentityAllocator struct {
	clusterIdentityConfigMapNamespace string
	clusterIdentityConfigMapName      string
	k8sClient                         clientset.Interface
}

// NewClusterIdentityAllocator creates a ClusterIdentityAllocator object
func NewClusterIdentityAllocator(
	clusterIdentityConfigMapNamespace string,
	clusterIdentityConfigMapName string,
	k8sClient clientset.Interface,
) *ClusterIdentityAllocator {
	return &ClusterIdentityAllocator{
		clusterIdentityConfigMapNamespace: clusterIdentityConfigMapNamespace,
		clusterIdentityConfigMapName:      clusterIdentityConfigMapName,
		k8sClient:                         k8sClient,
	}
}

func (a *ClusterIdentityAllocator) updateConfigMapIfNeeded() error {
	configMap, err := a.k8sClient.CoreV1().ConfigMaps(a.clusterIdentityConfigMapNamespace).Get(context.TODO(), a.clusterIdentityConfigMapName, metav1.GetOptions{})
	exists := true
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("error when getting '%s/%s' ConfigMap: %v", a.clusterIdentityConfigMapNamespace, a.clusterIdentityConfigMapName, err)
		}
		exists = false
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      a.clusterIdentityConfigMapName,
				Namespace: a.clusterIdentityConfigMapNamespace,
				Labels: map[string]string{
					"app": "antrea",
				},
			},
		}
	}

	// returns a triplet consisting of the cluster UUID, a boolean indicating if the UUID needs
	// to be written to the ConfigMap, and an error if applicable
	inspectUUID := func() (uuid.UUID, bool, error) {
		clusterUUIDStr, ok := configMap.Data[uuidConfigMapKey]
		if ok && clusterUUIDStr != "" {
			clusterUUID, err := uuid.Parse(clusterUUIDStr)
			if err != nil {
				return uuid.Nil, false, fmt.Errorf("cluster already has UUID '%s' but it is not valid: %v", clusterUUIDStr, err)
			}
			return clusterUUID, false, nil
		}

		// generate a new random UUID
		clusterUUID := uuid.New()

		return clusterUUID, true, nil
	}

	clusterUUID, clusterUUIDNeedsUpdate, err := inspectUUID()
	if err != nil {
		return err
	}
	if !clusterUUIDNeedsUpdate {
		klog.Infof("Existing cluster UUID: %v", clusterUUID)
		return nil
	}

	configMap.Data = map[string]string{
		uuidConfigMapKey: clusterUUID.String(),
	}
	if exists {
		if _, err := a.k8sClient.CoreV1().ConfigMaps(a.clusterIdentityConfigMapNamespace).Update(context.TODO(), configMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error when updating '%s/%s' ConfigMap with new cluster identity: %v", a.clusterIdentityConfigMapNamespace, a.clusterIdentityConfigMapName, err)
		}
	} else {
		if _, err := a.k8sClient.CoreV1().ConfigMaps(a.clusterIdentityConfigMapNamespace).Create(context.TODO(), configMap, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error when creating '%s/%s' ConfigMap with new cluster identity: %v", a.clusterIdentityConfigMapNamespace, a.clusterIdentityConfigMapName, err)
		}
	}
	klog.Infof("New cluster UUID: %v", clusterUUID)
	return nil
}

// Run will ensure that the antrea-cluster-identity ConfigMap is up-to-date. It is meant to be
// called asynchronously in its own goroutine, and will keep retrying in case of error, using an
// exponential backoff mechanism.
func (a *ClusterIdentityAllocator) Run(stopCh <-chan struct{}) {
	// Exponential backoff, starting at 100ms with a factor of 2. A "steps" value of 8 means we
	// will increase the backoff duration at most 8 times, so the max duration is (100ms * //
	// 2^8), which is about 25s.
	retry := wait.Backoff{
		Steps:    8,
		Duration: 100 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.0,
	}

	for {
		err := a.updateConfigMapIfNeeded()
		if err == nil {
			return
		}
		sleepDuration := retry.Step()
		klog.Errorf("Cannot validate or update cluster UUID because of the following error, will retry in %v: %v", sleepDuration, err)
		select {
		case <-stopCh:
			return
		case <-time.After(sleepDuration):
			continue
		}
	}
}

type ClusterIdentity struct {
	UUID uuid.UUID
}

// ClusterIdentityProvider is an interface used to retrieve the cluster identity information (UUID),
// as provided by the user or generated by the Antrea Controller. It also returns the time at which
// the antrea-cluster-identity was created, which can typically be considered as the time at which
// Antrea was deployed to the cluster.
type ClusterIdentityProvider interface {
	Get() (ClusterIdentity, time.Time, error)
}

type clusterIdentityProvider struct {
	clusterIdentityConfigMapNamespace string
	clusterIdentityConfigMapName      string
	k8sClient                         clientset.Interface
}

// NewClusterIdentityProvider returns a new object implementing the ClusterIdentityProvider
// interface.
func NewClusterIdentityProvider(
	clusterIdentityConfigMapNamespace string,
	clusterIdentityConfigMapName string,
	k8sClient clientset.Interface,
) *clusterIdentityProvider {
	return &clusterIdentityProvider{
		clusterIdentityConfigMapNamespace: clusterIdentityConfigMapNamespace,
		clusterIdentityConfigMapName:      clusterIdentityConfigMapName,
		k8sClient:                         k8sClient,
	}
}

// Get will retrieve the cluster identity (UUID) stored in the antrea-cluster-identity ConfigMap. In
// case of error, clients are invited to retry as the information may not be available yet.
func (p *clusterIdentityProvider) Get() (ClusterIdentity, time.Time, error) {
	var identity ClusterIdentity
	var creationTime time.Time

	configMap, err := p.k8sClient.CoreV1().ConfigMaps(p.clusterIdentityConfigMapNamespace).Get(context.TODO(), p.clusterIdentityConfigMapName, metav1.GetOptions{})
	if err != nil {
		return identity, creationTime, fmt.Errorf("error when getting '%s/%s' ConfigMap: %v", p.clusterIdentityConfigMapNamespace, p.clusterIdentityConfigMapName, err)
	}

	creationTime = configMap.CreationTimestamp.Time

	getUUID := func() error {
		clusterUUIDStr, ok := configMap.Data[uuidConfigMapKey]
		if !ok || clusterUUIDStr == "" {
			return fmt.Errorf("cluster UUID has not been set yet")
		}
		clusterUUID, err := uuid.Parse(clusterUUIDStr)
		if err != nil {
			return fmt.Errorf("cluster UUID cannot be parsed")
		}
		identity.UUID = clusterUUID
		return nil
	}

	if err := getUUID(); err != nil {
		return identity, creationTime, err
	}

	return identity, creationTime, nil
}
