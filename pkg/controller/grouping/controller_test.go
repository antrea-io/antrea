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

package grouping

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/features"
)

const informerDefaultResync = 30 * time.Second

func TestGroupEntityControllerRun(t *testing.T) {
	tests := []struct {
		name                    string
		initialPods             []*v1.Pod
		initialExternalEntities []*v1alpha2.ExternalEntity
		initialNamespaces       []*v1.Namespace
		antreaPolicyEnabled     bool
	}{
		{
			name:                    "AntreaPolicy enabled",
			initialPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			initialExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			initialNamespaces:       []*v1.Namespace{nsDefault, nsOther},
			antreaPolicyEnabled:     true,
		},
		{
			name:                "AntreaPolicy disabled",
			initialPods:         []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			initialNamespaces:   []*v1.Namespace{nsDefault, nsOther},
			antreaPolicyEnabled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.AntreaPolicy, tt.antreaPolicyEnabled)()
			var objs []runtime.Object
			for _, pod := range tt.initialPods {
				objs = append(objs, pod)
			}
			for _, namespace := range tt.initialNamespaces {
				objs = append(objs, namespace)
			}
			var crdObjs []runtime.Object
			for _, externalEntity := range tt.initialExternalEntities {
				crdObjs = append(crdObjs, externalEntity)
			}
			index := NewGroupEntityIndex()
			client := fake.NewSimpleClientset(objs...)
			crdClient := fakeversioned.NewSimpleClientset(crdObjs...)
			informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
			crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
			stopCh := make(chan struct{})

			c := NewGroupEntityController(index, informerFactory.Core().V1().Pods(), informerFactory.Core().V1().Namespaces(), crdInformerFactory.Crd().V1alpha2().ExternalEntities())
			assert.False(t, index.HasSynced(), "GroupEntityIndex has been synced before starting InformerFactories")

			informerFactory.Start(stopCh)
			crdInformerFactory.Start(stopCh)
			assert.False(t, index.HasSynced(), "GroupEntityIndex has been synced before starting GroupEntityController")
			go c.Run(stopCh)

			assert.NoError(t, wait.Poll(10*time.Millisecond, time.Second, func() (done bool, err error) {
				return index.HasSynced(), nil
			}), "GroupEntityIndex hasn't been synced in 1 second after starting GroupEntityController")
			assert.Len(t, tt.initialPods, index.initialPodCount)
			assert.Len(t, tt.initialPods, index.accumulatedPodCount)
			assert.Len(t, tt.initialPods, index.currentPodCount)
			assert.Len(t, tt.initialNamespaces, index.initialNamespaceCount)
			assert.Len(t, tt.initialNamespaces, index.accumulatedNamespaceCount)
			assert.Len(t, tt.initialNamespaces, len(index.namespaceLabels))
			assert.Len(t, tt.initialExternalEntities, index.initialExternalEntityCount)
			assert.Len(t, tt.initialExternalEntities, index.accumulatedExternalEntityCount)
			assert.Len(t, tt.initialExternalEntities, index.currentExternalEntityCount)
		})
	}
}
