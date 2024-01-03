// Copyright 2022 Antrea Authors
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

package labelidentity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	fakeversioned "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
)

const informerDefaultResync = 30 * time.Second

var (
	labelIdentityA = &mcv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clusterA-3de4f2hdf1",
		},
		Spec: mcv1alpha1.LabelIdentitySpec{
			Label: labelA,
			ID:    1,
		},
	}
	labelIdentityB = &mcv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clusterA-23few454fg",
		},
		Spec: mcv1alpha1.LabelIdentitySpec{
			Label: labelB,
			ID:    2,
		},
	}
)

func TestGroupEntityControllerRun(t *testing.T) {
	// Even with only 1 buffer, the code should work as expected - as opposed to hanging somewhere.
	originalEventChanSize := eventChanSize
	eventChanSize = 1
	defer func() {
		eventChanSize = originalEventChanSize
	}()

	index := NewLabelIdentityIndex()
	var objs []runtime.Object
	initialLabelIdentities := []*mcv1alpha1.LabelIdentity{labelIdentityA, labelIdentityB}
	for _, l := range initialLabelIdentities {
		objs = append(objs, l)
	}
	mcClient := fakeversioned.NewSimpleClientset(objs...)
	mcInformerFactory := crdinformers.NewSharedInformerFactory(mcClient, informerDefaultResync)
	stopCh := make(chan struct{})

	c := NewLabelIdentityController(index, mcInformerFactory.Multicluster().V1alpha1().LabelIdentities())
	assert.False(t, index.HasSynced(), "LabelIdentityIndex has been synced before starting InformerFactories")

	mcInformerFactory.Start(stopCh)
	assert.False(t, index.HasSynced(), "LabelIdentityIndex has been synced before starting LabelIdentityController")

	go c.labelIdentityIndex.Run(stopCh)
	go c.Run(stopCh)

	assert.Eventually(t, func() bool {
		return index.HasSynced()
	}, 1*time.Second, 10*time.Millisecond, "LabelIdentityIndex hasn't been synced in 1 second after starting LabelIdentityController")
}
