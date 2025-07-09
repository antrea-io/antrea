// Copyright 2025 Antrea Authors
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

package objectstore

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/util/k8s"
)

const serviceNameIndex = "serviceName"

// ServiceStore interface provides Service-specific operations
type ServiceStore interface {
	GetServiceByNamespacedNameAndTime(namespacedName string, startTime time.Time) (*corev1.Service, bool)
	Run(stopCh <-chan struct{})
	HasSynced() bool
}

// serviceStore embeds ObjectStore[*corev1.Service] to provide Service-specific methods
type serviceStore struct {
	*ObjectStore[*corev1.Service]
}

// Validate that *serviceStore implements the ServiceStore interface
var _ ServiceStore = &serviceStore{}

func NewServiceStore(serviceInformer cache.SharedIndexInformer) *serviceStore {
	config := StoreConfig[*corev1.Service]{
		DeleteQueueName: "serviceStoreServicesToDelete",
		Indexers:        cache.Indexers{serviceNameIndex: serviceNameIndexFunc},
	}
	return &serviceStore{
		ObjectStore: NewObjectStore(serviceInformer, config),
	}
}

// GetServiceByNamespacedNameAndTime provides a Service-specific method for getting Services by name and time
func (s *serviceStore) GetServiceByNamespacedNameAndTime(namespacedName string, startTime time.Time) (*corev1.Service, bool) {
	return s.GetObjectByIndexAndTime(serviceNameIndex, namespacedName, startTime)
}

func serviceNameIndexFunc(obj interface{}) ([]string, error) {
	service, ok := obj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("obj is not Service: %+v", obj)
	}
	return []string{k8s.NamespacedName(service.Namespace, service.Name)}, nil
}
