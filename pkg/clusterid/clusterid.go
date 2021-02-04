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

package clusterid

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

const (
	DefaultClusterIDConfigMapName = "antrea-cluster-id"
	uuidConfigMapKey              = "uuid"
	nameConfigMapKey              = "name"
)

// ClusterIDAllocator ensures that the antrea-cluster-id ConfigMap is populated correctly, with a
// name and a UUID. It is meant to be used by the Antrea Controller.
type ClusterIDAllocator struct {
	clusterIDConfigMapNamespace string
	clusterIDConfigMapName      string
	k8sClient                   clientset.Interface
	userProvidedName            string
	userProvidedUUID            *uuid.UUID
}

// NewClusterIDAllocator creates a ClusterIDAllocator object. If userProvidedName is empty,
// userProvidedUUID will be used as the name. If userProvidedUUID is empty, a new random UUID will
// be generated.
func NewClusterIDAllocator(
	clusterIDConfigMapNamespace string,
	clusterIDConfigMapName string,
	k8sClient clientset.Interface,
	userProvidedName string,
	userProvidedUUID string,
) (*ClusterIDAllocator, error) {
	var userProvidedUUIDParsed *uuid.UUID
	if userProvidedUUID != "" {
		parsedUUID, err := uuid.Parse(userProvidedUUID)
		if err != nil {
			return nil, fmt.Errorf("Invalid UUID '%s': %v", userProvidedUUID, err)
		}
		userProvidedUUIDParsed = &parsedUUID
	}
	return &ClusterIDAllocator{
		clusterIDConfigMapNamespace: clusterIDConfigMapNamespace,
		clusterIDConfigMapName:      clusterIDConfigMapName,
		k8sClient:                   k8sClient,
		userProvidedName:            userProvidedName,
		userProvidedUUID:            userProvidedUUIDParsed,
	}, nil
}

// Run will ensure that the antrea-cluster-id ConfigMap is up-to-date. It is meant to be called
// asynchronously in its own goroutine, and will keep retrying in case of error, using an
// exponential backoff mechanism.
func (a *ClusterIDAllocator) Run(stopCh <-chan struct{}) {
	inspectUUID := func(configMap *corev1.ConfigMap) (uuid.UUID, bool, error) {
		clusterUUIDStr, ok := configMap.Data[uuidConfigMapKey]
		if ok && clusterUUIDStr != "" {
			clusterUUID, err := uuid.Parse(clusterUUIDStr)
			if err != nil {
				return uuid.Nil, false, fmt.Errorf("cluster already has UUID '%s' but it is not valid: %v", clusterUUIDStr, err)
			}
			if a.userProvidedUUID != nil && *a.userProvidedUUID != clusterUUID {
				return uuid.Nil, false, fmt.Errorf("cluster already has UUID '%v', which does not match the user-provided one '%v'", clusterUUID, *a.userProvidedUUID)
			}
			return clusterUUID, false, nil
		}

		// need to update cluster UUID
		var clusterUUID uuid.UUID
		if a.userProvidedUUID != nil {
			clusterUUID = *a.userProvidedUUID
		} else {
			clusterUUID = uuid.New()
		}
		return clusterUUID, true, nil
	}

	inspectName := func(configMap *corev1.ConfigMap, clusterUUID uuid.UUID) (string, bool, error) {
		clusterName, ok := configMap.Data[nameConfigMapKey]
		if ok && clusterName != "" {
			if a.userProvidedName != "" && a.userProvidedName != clusterName {
				klog.Warningf("cluster already has name %s, which does not match the user-provided one '%s'; current name will be overwritten", clusterName, a.userProvidedName)
			} else {
				return clusterName, false, nil
			}
		}

		// need to update cluster name
		if a.userProvidedName != "" {
			clusterName = a.userProvidedName
		} else {
			clusterName = clusterUUID.String()
		}
		return clusterName, true, nil
	}

	updateConfigMapIfNeeded := func() error {
		configMap, err := a.k8sClient.CoreV1().ConfigMaps(a.clusterIDConfigMapNamespace).Get(context.TODO(), a.clusterIDConfigMapName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error when getting '%s/%s' ConfigMap: %v", a.clusterIDConfigMapNamespace, a.clusterIDConfigMapName, err)
		}
		clusterUUID, clusterUUIDNeedsUpdate, err := inspectUUID(configMap)
		if err != nil {
			return err
		}
		if !clusterUUIDNeedsUpdate {
			klog.Infof("Existing cluster UUID: %v", clusterUUID)
		}
		clusterName, clusterNameNeedsUpdate, err := inspectName(configMap, clusterUUID)
		if err != nil {
			return err
		}
		if !clusterNameNeedsUpdate {
			klog.Infof("Existing cluster name: %s", clusterName)
		}

		// update ConfigMap if needed
		if !clusterUUIDNeedsUpdate && !clusterNameNeedsUpdate {
			return nil
		}
		configMap.Data = map[string]string{
			uuidConfigMapKey: clusterUUID.String(),
			nameConfigMapKey: clusterName,
		}
		if _, err := a.k8sClient.CoreV1().ConfigMaps(a.clusterIDConfigMapNamespace).Update(context.TODO(), configMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error when updating '%s/%s' ConfigMap with new cluster identity: %v", a.clusterIDConfigMapNamespace, a.clusterIDConfigMapName, err)
		}
		if clusterUUIDNeedsUpdate {
			klog.Infof("New cluster UUID: %v", clusterUUID)
		}
		if clusterNameNeedsUpdate {
			klog.Infof("New cluster name: %s", clusterName)
		}
		return nil
	}

	// exponential backoff, starting at 100ms with a factor of 2. A "steps" value of 10 means we
	// will increase the backoff duration at most 10 times, so the max duration is (100ms * //
	// 2^8), which is about 25s.
	retry := wait.Backoff{
		Steps:    8,
		Duration: 100 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.0,
	}

	for {
		err := updateConfigMapIfNeeded()
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

// ClusterIDProvider is an interface used to retrieve the cluster identity information (name and
// UUID), as provided by the user or generated by the Antrea Controller.
type ClusterIDProvider interface {
	Get() (uuid.UUID, string, error)
}

type clusterIDProvider struct {
	clusterIDConfigMapNamespace string
	clusterIDConfigMapName      string
	k8sClient                   clientset.Interface
}

// NewClusterIDProvider returns a new object implementing the ClusterIDProvider interface.
func NewClusterIDProvider(
	clusterIDConfigMapNamespace string,
	clusterIDConfigMapName string,
	k8sClient clientset.Interface,
) ClusterIDProvider {
	return &clusterIDProvider{
		clusterIDConfigMapNamespace: clusterIDConfigMapNamespace,
		clusterIDConfigMapName:      clusterIDConfigMapName,
		k8sClient:                   k8sClient,
	}
}

// Get will retrieve the cluster identity stored in the antrea-cluster-id ConfigMap. In case of
// error, clients are invited to retry as the information may not be available yet.
func (p *clusterIDProvider) Get() (uuid.UUID, string, error) {
	configMap, err := p.k8sClient.CoreV1().ConfigMaps(p.clusterIDConfigMapNamespace).Get(context.TODO(), p.clusterIDConfigMapName, metav1.GetOptions{})
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("error when getting '%s/%s' ConfigMap: %v", p.clusterIDConfigMapNamespace, p.clusterIDConfigMapName, err)
	}

	getUUID := func() (uuid.UUID, error) {
		clusterUUIDStr, ok := configMap.Data[uuidConfigMapKey]
		if !ok || clusterUUIDStr == "" {
			return uuid.Nil, fmt.Errorf("cluster UUID has not been set yet")
		}
		clusterUUID, err := uuid.Parse(clusterUUIDStr)
		if err != nil {
			return uuid.Nil, fmt.Errorf("cluster UUID cannot be parsed")
		}
		return clusterUUID, nil
	}

	getName := func() (string, error) {
		clusterName, ok := configMap.Data[nameConfigMapKey]
		if !ok || clusterName == "" {
			return "", fmt.Errorf("cluster name has not been set yet")
		}
		return clusterName, nil
	}

	clusterUUID, err := getUUID()
	if err != nil {
		return uuid.Nil, "", err
	}
	clusterName, err := getName()
	if err != nil {
		return uuid.Nil, "", err
	}
	return clusterUUID, clusterName, nil
}
