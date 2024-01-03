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

package supportbundlecollection

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	fakeclientset "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	bundlecollectionstore "antrea.io/antrea/pkg/controller/supportbundlecollection/store"
	"antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	informerDefaultResync = 30 * time.Second

	testKeyString       = "it is a valid API key"
	testTokenString     = "it is a valid token"
	secretWithAPIKey    = "s1"
	secretWithToken     = "s2"
	secretWithBasicAuth = "s3"
	secretNamespace     = "ns"
)

type bundleNodes struct {
	names  []string
	labels map[string]string
}

type bundleExternalNodes struct {
	namespace string
	names     []string
	labels    map[string]string
}

type bundlePhase int

const (
	pending bundlePhase = iota
	processing
	completed
)

type bundleConfig struct {
	name            string
	nodes           *bundleNodes
	externalNodes   *bundleExternalNodes
	authType        v1alpha1.BundleServerAuthType
	secretName      string
	secretNamespace string
	conditions      []v1alpha1.SupportBundleCollectionCondition
	phase           bundlePhase
	createTime      *time.Time
}

func TestReconcileSupportBundles(t *testing.T) {
	// Prepare test resources.
	testConfigs := testBundleConfigs()
	nodeConfigs, externalNodeConfigs := parseDependentResources(testConfigs)
	coreObjects := prepareNodes(nodeConfigs)
	crdObjects := prepareExternalNodes(externalNodeConfigs)
	for _, c := range prepareBundleCollections(testConfigs) {
		crdObjects = append(crdObjects, c)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret1",
			Namespace: "default",
		},
		Data: map[string][]byte{
			secretKeyWithAPIKey: []byte(base64.StdEncoding.EncodeToString([]byte("a valid API key"))),
		},
	}
	coreObjects = append(coreObjects, secret)

	testClient := newTestClient(coreObjects, crdObjects)
	controller := newController(testClient)
	stopCh := make(chan struct{})
	testClient.start(stopCh)
	testClient.waitForSync(stopCh)

	processingBundleCollections := sets.New[string]()
	ignoredBundleCollections := sets.New[string]()
	for _, c := range testConfigs {
		if c.phase == processing {
			processingBundleCollections.Insert(c.name)
		} else {
			ignoredBundleCollections.Insert(c.name)
		}
	}

	err := controller.reconcileSupportBundleCollections()
	assert.NoError(t, err)

	for name := range processingBundleCollections {
		_, exists, _ := controller.supportBundleCollectionStore.Get(name)
		assert.True(t, exists)
		_, appliedToExists, _ := controller.supportBundleCollectionAppliedToStore.GetByKey(name)
		assert.True(t, appliedToExists)
	}

	for name := range ignoredBundleCollections {
		_, exists, _ := controller.supportBundleCollectionStore.Get(name)
		assert.False(t, exists)
		_, appliedToExists, _ := controller.supportBundleCollectionAppliedToStore.GetByKey(name)
		assert.False(t, appliedToExists)
	}
}

func parseDependentResources(configs []bundleConfig) ([]nodeConfig, []externalNodeConfig) {
	nodeNames := sets.New[string]()
	nodeLabels := make(map[string]string)
	externalNodeNames := make(map[string]sets.Set[string])
	externalNodeLabels := make(map[string]map[string]string)
	for _, cfg := range configs {
		if cfg.nodes != nil {
			for _, name := range cfg.nodes.names {
				nodeNames.Insert(name)
			}
			for k, v := range cfg.nodes.labels {
				nodeLabels[k] = v
			}
		}
		if cfg.externalNodes != nil {
			_, exists := externalNodeNames[cfg.externalNodes.namespace]
			if !exists {
				externalNodeNames[cfg.externalNodes.namespace] = sets.New[string]()
			}
			for _, name := range cfg.externalNodes.names {
				externalNodeNames[cfg.externalNodes.namespace].Insert(name)
			}
			if len(cfg.externalNodes.labels) > 0 {
				externalNodeLabels[cfg.externalNodes.namespace] = cfg.externalNodes.labels
			}
		}
	}
	var nodeConfigs []nodeConfig
	var externalNodeConfigs []externalNodeConfig
	for name := range nodeNames {
		nodeConfigs = append(nodeConfigs, nodeConfig{name: name})
	}
	nodeConfigs = append(nodeConfigs, nodeConfig{
		name:   "selected-node",
		labels: nodeLabels,
	})
	for ns, names := range externalNodeNames {
		for name := range names {
			externalNodeConfigs = append(externalNodeConfigs, externalNodeConfig{
				namespace: ns,
				name:      name,
			})
		}
	}
	for ns, labels := range externalNodeLabels {
		externalNodeConfigs = append(externalNodeConfigs, externalNodeConfig{
			namespace: ns,
			name:      fmt.Sprintf("%s-selected-externalnode", ns),
			labels:    labels,
		})
	}
	return nodeConfigs, externalNodeConfigs
}

func TestAddSupportBundleCollection(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		supportBundleCollection *v1alpha1.SupportBundleCollection
		expectedItem            string
	}{
		{
			name: "bundle-created",
			supportBundleCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bundle1",
				},
				Spec: v1alpha1.SupportBundleCollectionSpec{
					Nodes: &v1alpha1.BundleNodes{
						NodeNames: []string{"n1", "n2"},
					},
					ExternalNodes: &v1alpha1.BundleExternalNodes{
						Namespace: "ns1",
						NodeNames: []string{"en1"},
					},
				},
			},
			expectedItem: "bundle1",
		},
		{
			name: "bundle-started",
			supportBundleCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bundle2",
				},
				Spec: v1alpha1.SupportBundleCollectionSpec{
					ExternalNodes: &v1alpha1.BundleExternalNodes{
						Namespace: "ns2",
						NodeNames: []string{"en3"},
					},
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{
							Type:   v1alpha1.CollectionStarted,
							Status: metav1.ConditionTrue,
						},
					},
				},
			},
			expectedItem: "bundle2",
		},
		{
			name: "bundle-expired",
			supportBundleCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bundle3",
				},
				Spec: v1alpha1.SupportBundleCollectionSpec{
					ExternalNodes: &v1alpha1.BundleExternalNodes{
						Namespace: "ns2",
					},
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{
							Type:   v1alpha1.CollectionStarted,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.CollectionCompleted,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.CollectionFailure,
							Status: metav1.ConditionTrue,
							Reason: string(metav1.StatusReasonExpired),
						},
					},
				},
			},
		},
		{
			name: "bundle-failed-start",
			supportBundleCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bundle4",
				},
				Spec: v1alpha1.SupportBundleCollectionSpec{
					ExternalNodes: &v1alpha1.BundleExternalNodes{
						Namespace: "ns2",
					},
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{
							Type:   v1alpha1.CollectionStarted,
							Status: metav1.ConditionFalse,
							Reason: string(metav1.StatusReasonConflict),
						},
					},
				},
			},
			expectedItem: "bundle4",
		},
		{
			name: "bundle-partial-success",
			supportBundleCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bundle5",
				},
				Spec: v1alpha1.SupportBundleCollectionSpec{
					ExternalNodes: &v1alpha1.BundleExternalNodes{
						Namespace: "ns5",
						NodeSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "bundle-test"},
						},
					},
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{
							Type:   v1alpha1.CollectionStarted,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.BundleCollected,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.CollectionCompleted,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.CollectionFailure,
							Status: metav1.ConditionTrue,
							Reason: "Time is expired",
						},
					},
				},
			},
		},
		{
			name: "bundle-success",
			supportBundleCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bundle6",
				},
				Spec: v1alpha1.SupportBundleCollectionSpec{
					Nodes: &v1alpha1.BundleNodes{
						NodeNames: []string{"n1", "n6"},
					},
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{
							Type:   v1alpha1.CollectionStarted,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.BundleCollected,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.CollectionCompleted,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   v1alpha1.CollectionFailure,
							Status: metav1.ConditionFalse,
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testClient := newTestClient(nil, nil)
			controller := &Controller{
				crdClient: testClient.crdClient,
				queue:     workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "supportBundle"),
			}
			controller.addSupportBundleCollection(tc.supportBundleCollection)
			if tc.expectedItem != "" {
				assert.Equal(t, 1, controller.queue.Len())
				gotItem, _ := controller.queue.Get()
				assert.Equal(t, tc.expectedItem, gotItem)
			} else {
				assert.Equal(t, 0, controller.queue.Len())
			}
		})
	}
}

func TestSupportBundleCollectionEvents(t *testing.T) {
	existingBundleCollection := generateSupportBundleResource(bundleConfig{
		name:            "b0",
		externalNodes:   &bundleExternalNodes{namespace: "ns1"},
		authType:        v1alpha1.APIKey,
		secretName:      "s1",
		secretNamespace: "default",
		conditions: []v1alpha1.SupportBundleCollectionCondition{
			{
				Type:   v1alpha1.CollectionStarted,
				Status: metav1.ConditionTrue,
			}, {
				Type:   v1alpha1.BundleCollected,
				Status: metav1.ConditionTrue,
			},
		},
	})
	testClient := newTestClient(nil, []runtime.Object{existingBundleCollection})
	controller := newController(testClient)

	stopCh := make(chan struct{})
	testClient.start(stopCh)
	testClient.waitForSync(stopCh)

	enqueuedBundleNameCountMappings := make(map[string]int)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		processNextWorkItem := func() bool {
			obj, quit := controller.queue.Get()
			if quit {
				return false
			}
			defer controller.queue.Done(obj)
			key, _ := obj.(string)
			if _, exists := enqueuedBundleNameCountMappings[key]; !exists {
				enqueuedBundleNameCountMappings[key] = 0
			}
			enqueuedBundleNameCountMappings[key] += 1
			controller.queue.Forget(key)
			return true
		}
		for processNextWorkItem() {
		}
		wg.Done()
	}()

	testBundleConfig := generateSupportBundleResource(bundleConfig{
		name:            "b1",
		nodes:           &bundleNodes{},
		authType:        v1alpha1.APIKey,
		secretName:      "s1",
		secretNamespace: "default",
	})
	bundleCollection, err := testClient.crdClient.CrdV1alpha1().SupportBundleCollections().Create(context.TODO(), testBundleConfig, metav1.CreateOptions{})
	require.NoError(t, err)
	time.Sleep(time.Millisecond * 200)

	updateBundleStatus := func(oriBundleCollection *v1alpha1.SupportBundleCollection, updatedStatus v1alpha1.SupportBundleCollectionStatus) {
		collection := &v1alpha1.SupportBundleCollection{
			ObjectMeta: oriBundleCollection.ObjectMeta,
			Spec:       oriBundleCollection.Spec,
			Status:     updatedStatus,
		}
		_, err := testClient.crdClient.CrdV1alpha1().SupportBundleCollections().UpdateStatus(context.TODO(), collection, metav1.UpdateOptions{})
		require.NoError(t, err)
		time.Sleep(time.Millisecond * 200)
	}

	updateBundleStatus(bundleCollection, v1alpha1.SupportBundleCollectionStatus{
		DesiredNodes:   10,
		CollectedNodes: 0,
		Conditions: []v1alpha1.SupportBundleCollectionCondition{
			{
				Type:   v1alpha1.CollectionStarted,
				Status: metav1.ConditionTrue,
			},
		},
	})
	updateBundleStatus(bundleCollection, v1alpha1.SupportBundleCollectionStatus{
		DesiredNodes:   10,
		CollectedNodes: 1,
		Conditions: []v1alpha1.SupportBundleCollectionCondition{
			{
				Type:   v1alpha1.CollectionStarted,
				Status: metav1.ConditionTrue,
			}, {
				Type:   v1alpha1.BundleCollected,
				Status: metav1.ConditionTrue,
			},
		},
	})
	updateBundleStatus(existingBundleCollection, v1alpha1.SupportBundleCollectionStatus{
		DesiredNodes:   10,
		CollectedNodes: 5,
		Conditions: []v1alpha1.SupportBundleCollectionCondition{
			{
				Type:   v1alpha1.CollectionStarted,
				Status: metav1.ConditionTrue,
			}, {
				Type:   v1alpha1.BundleCollected,
				Status: metav1.ConditionTrue,
			},
		},
	})
	updateBundleStatus(existingBundleCollection, v1alpha1.SupportBundleCollectionStatus{
		DesiredNodes:   10,
		CollectedNodes: 7,
		Conditions: []v1alpha1.SupportBundleCollectionCondition{
			{
				Type:   v1alpha1.CollectionStarted,
				Status: metav1.ConditionTrue,
			}, {
				Type:   v1alpha1.BundleCollected,
				Status: metav1.ConditionTrue,
			},
			{
				Type:   v1alpha1.CollectionFailure,
				Status: metav1.ConditionTrue,
			},
		},
	})
	err = testClient.crdClient.CrdV1alpha1().SupportBundleCollections().Delete(context.TODO(), testBundleConfig.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
	// Wait for data sync
	time.Sleep(time.Millisecond * 200)
	controller.queue.ShutDown()
	wg.Wait()
	eventCount, exists := enqueuedBundleNameCountMappings[testBundleConfig.Name]
	assert.True(t, exists)
	assert.Equal(t, 4, eventCount)
	eventCount2, exists2 := enqueuedBundleNameCountMappings[existingBundleCollection.Name]
	assert.True(t, exists2)
	assert.Equal(t, 2, eventCount2)
}

type nodeConfig struct {
	name   string
	labels map[string]string
}

func TestGetBundleNodes(t *testing.T) {
	nodeObjects := prepareNodes([]nodeConfig{
		{name: "n1"},
		{name: "n2"},
		{name: "n3", labels: map[string]string{"test": "selected"}},
		{name: "n4", labels: map[string]string{"test": "selected"}},
		{name: "n5", labels: map[string]string{"test": "not-selected"}},
	})
	testClient := newTestClient(nodeObjects, nil)
	nodeInformer := testClient.informerFactory.Core().V1().Nodes()
	controller := &Controller{
		nodeLister: nodeInformer.Lister(),
	}
	stopCh := make(chan struct{})
	testClient.start(stopCh)

	testClient.waitForSync(stopCh)

	for _, tc := range []struct {
		bundleNodes   *v1alpha1.BundleNodes
		expectedNodes sets.Set[string]
	}{
		{
			bundleNodes: &v1alpha1.BundleNodes{
				NodeNames: []string{"n1", "n2"},
			},
			expectedNodes: sets.New[string]("n1", "n2"),
		}, {
			bundleNodes: &v1alpha1.BundleNodes{
				NodeSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"test": "selected"},
				},
			},
			expectedNodes: sets.New[string]("n3", "n4"),
		}, {
			bundleNodes: &v1alpha1.BundleNodes{
				NodeNames: []string{"n1", "n2"},
				NodeSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"test": "selected"},
				},
			},
			expectedNodes: sets.New[string]("n1", "n2", "n3", "n4"),
		}, {
			bundleNodes:   &v1alpha1.BundleNodes{},
			expectedNodes: sets.New[string]("n1", "n2", "n3", "n4", "n5"),
		}, {
			bundleNodes:   nil,
			expectedNodes: sets.New[string](),
		}, {
			bundleNodes: &v1alpha1.BundleNodes{
				NodeNames: []string{"n1", "not-exist"},
			},
			expectedNodes: sets.New[string]("n1"),
		},
	} {
		actualNodes, err := controller.getBundleNodes(tc.bundleNodes)
		assert.NoError(t, err, "failed to run getBundleNodes")
		assert.Equal(t, tc.expectedNodes, actualNodes)
	}
}

type externalNodeConfig struct {
	namespace string
	name      string
	labels    map[string]string
}

func TestGetBundleExternalNodes(t *testing.T) {
	externalNodeObjects := prepareExternalNodes([]externalNodeConfig{
		{namespace: "ns1", name: "n1"},
		{namespace: "ns1", name: "n2"},
		{namespace: "ns1", name: "n3", labels: map[string]string{"test": "selected"}},
		{namespace: "ns1", name: "n4", labels: map[string]string{"test": "not-selected"}},
		{namespace: "ns2", name: "n5", labels: map[string]string{"test": "selected"}},
		{namespace: "ns2", name: "n6", labels: map[string]string{"test": "selected"}},
	})
	testClient := newTestClient(nil, externalNodeObjects)
	externalNodeInformer := testClient.crdInformerFactory.Crd().V1alpha1().ExternalNodes()
	controller := &Controller{
		externalNodeLister: externalNodeInformer.Lister(),
	}
	stopCh := make(chan struct{})
	testClient.start(stopCh)

	testClient.waitForSync(stopCh)

	for _, tc := range []struct {
		bundleNodes   *v1alpha1.BundleExternalNodes
		expectedNodes sets.Set[string]
	}{
		{
			bundleNodes: &v1alpha1.BundleExternalNodes{
				Namespace: "ns1",
				NodeNames: []string{"n1", "n2"},
			},
			expectedNodes: sets.New[string]("ns1/n1", "ns1/n2"),
		}, {
			bundleNodes: &v1alpha1.BundleExternalNodes{
				Namespace: "ns1",
				NodeNames: []string{"n1"},
				NodeSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"test": "selected"},
				},
			},
			expectedNodes: sets.New[string]("ns1/n1", "ns1/n3"),
		}, {
			bundleNodes: &v1alpha1.BundleExternalNodes{
				Namespace: "ns1",
			},
			expectedNodes: sets.New[string]("ns1/n1", "ns1/n2", "ns1/n3", "ns1/n4"),
		}, {
			bundleNodes:   nil,
			expectedNodes: sets.New[string](),
		},
		{
			bundleNodes: &v1alpha1.BundleExternalNodes{
				Namespace: "ns1",
				NodeNames: []string{"not-exist"},
			},
			expectedNodes: sets.New[string](),
		},
	} {
		actualNodes, err := controller.getBundleExternalNodes(tc.bundleNodes)
		assert.NoError(t, err)
		assert.Equal(t, tc.expectedNodes, actualNodes)
	}
}

type secretConfig struct {
	name string
	data map[string][]byte
}

func TestParseBundleAuth(t *testing.T) {
	ns := "ns-auth"
	apiKey := testKeyString
	token := testTokenString
	usr := "user"
	pwd := "pwd123456"
	var secretObjects []runtime.Object
	for _, s := range prepareSecrets(ns, []secretConfig{
		{name: "s1", data: map[string][]byte{secretKeyWithAPIKey: []byte(apiKey)}},
		{name: "s2", data: map[string][]byte{secretKeyWithBearerToken: []byte(token)}},
		{name: "s3", data: map[string][]byte{secretKeyWithUsername: []byte(usr), secretKeyWithPassword: []byte(pwd)}},
		{name: "invalid-base64", data: map[string][]byte{secretKeyWithAPIKey: []byte("invalid string to decode with base64")}},
		{name: "invalid-secret", data: map[string][]byte{"unknown": []byte(apiKey)}},
	}) {
		secretObjects = append(secretObjects, s)
	}

	testClient := newTestClient(secretObjects, nil)
	controller := newController(testClient)
	stopCh := make(chan struct{})
	testClient.start(stopCh)

	testClient.waitForSync(stopCh)

	for _, tc := range []struct {
		authentication v1alpha1.BundleServerAuthConfiguration
		expectedError  string
		expectedAuth   *controlplane.BundleServerAuthConfiguration
	}{
		{
			authentication: v1alpha1.BundleServerAuthConfiguration{
				AuthType: v1alpha1.APIKey,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s1",
				},
			},
			expectedAuth: &controlplane.BundleServerAuthConfiguration{
				APIKey: testKeyString,
			},
		},
		{
			authentication: v1alpha1.BundleServerAuthConfiguration{
				AuthType: v1alpha1.BearerToken,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s2",
				},
			},
			expectedAuth: &controlplane.BundleServerAuthConfiguration{
				BearerToken: testTokenString,
			},
		},
		{
			authentication: v1alpha1.BundleServerAuthConfiguration{
				AuthType: v1alpha1.BasicAuthentication,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s3",
				},
			},
			expectedAuth: &controlplane.BundleServerAuthConfiguration{
				BasicAuthentication: &controlplane.BasicAuthentication{
					Username: usr,
					Password: pwd,
				},
			},
		},
		{
			authentication: v1alpha1.BundleServerAuthConfiguration{
				AuthType: v1alpha1.BearerToken,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "invalid-secret",
				},
			},
			expectedError: fmt.Sprintf("not found authentication in Secret %s/invalid-secret with key %s", ns, secretKeyWithBearerToken),
		},
		{
			authentication: v1alpha1.BundleServerAuthConfiguration{
				AuthType: v1alpha1.BearerToken,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "not-exist",
				},
			},
			expectedError: fmt.Sprintf("unable to get Secret with name not-exist in Namespace %s", ns),
		},
		{
			authentication: v1alpha1.BundleServerAuthConfiguration{
				AuthType:   v1alpha1.APIKey,
				AuthSecret: nil,
			},
			expectedError: "authentication is not specified",
		},
	} {
		auth, err := controller.parseBundleAuth(tc.authentication)
		if tc.expectedError != "" {
			assert.Contains(t, err.Error(), tc.expectedError)
		} else {
			assert.Equal(t, tc.expectedAuth, auth)
		}
	}
}

func TestCreateAndDeleteInternalSupportBundleCollection(t *testing.T) {
	coreObjects, crdObjects := prepareTopology()
	testClient := newTestClient(coreObjects, crdObjects)
	controller := newController(testClient)
	stopCh := make(chan struct{})
	testClient.start(stopCh)

	testClient.waitForSync(stopCh)

	expiredDuration, _ := time.ParseDuration("-61m")
	expiredCreationTime := time.Now().Add(expiredDuration)
	testCases := []struct {
		bundleConfig
		expectedNodes sets.Set[string]
		expectedAuth  controlplane.BundleServerAuthConfiguration
		expectedError string
		expectFailure bool
	}{
		{
			bundleConfig: bundleConfig{
				name: "b1",
				nodes: &bundleNodes{
					names:  []string{"n1", "n2"},
					labels: map[string]string{"test": "selected"},
				},
				authType: v1alpha1.APIKey,
			},
			expectedNodes: sets.New[string]("n1", "n2", "n3", "n4"),
			expectedAuth: controlplane.BundleServerAuthConfiguration{
				APIKey: testKeyString,
			},
		},
		{
			bundleConfig: bundleConfig{
				name: "b2",
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					names:     []string{"en1", "en2"},
					labels:    map[string]string{"test": "selected"},
				},
				authType: v1alpha1.APIKey,
			},
			expectedNodes: sets.New[string]("ns1/en1", "ns1/en2", "ns1/en3"),
			expectedAuth: controlplane.BundleServerAuthConfiguration{
				APIKey: testKeyString,
			},
		},
		{
			bundleConfig: bundleConfig{
				name: "b3",
				nodes: &bundleNodes{
					names: []string{"n1", "n2"},
				},
				externalNodes: &bundleExternalNodes{
					namespace: "ns2",
				},
				authType: v1alpha1.APIKey,
			},
			expectedNodes: sets.New[string]("n1", "n2", "ns2/en5"),
			expectedAuth: controlplane.BundleServerAuthConfiguration{
				APIKey: testKeyString,
			},
		},
		{
			bundleConfig: bundleConfig{
				name: "b4",
				externalNodes: &bundleExternalNodes{
					namespace: "ns2",
				},
				authType:        v1alpha1.BearerToken,
				secretName:      "s4",
				secretNamespace: secretNamespace,
			},
			expectedError: fmt.Sprintf("unable to get Secret with name s4 in Namespace %s", secretNamespace),
		},
		{
			bundleConfig: bundleConfig{
				name: "b5",
				externalNodes: &bundleExternalNodes{
					namespace: "ns2",
				},
				authType:   v1alpha1.BearerToken,
				createTime: &expiredCreationTime,
			},
			expectFailure: true,
		},
	}

	for _, tc := range testCases {
		bundleConfig := tc.bundleConfig
		if bundleConfig.secretName == "" {
			secretName := secretWithAPIKey
			if tc.bundleConfig.authType == v1alpha1.BearerToken {
				secretName = secretWithToken
			}
			bundleConfig.secretName = secretName
			bundleConfig.secretNamespace = secretNamespace
		}
		bundle, err := testClient.crdClient.CrdV1alpha1().SupportBundleCollections().Create(context.TODO(), generateSupportBundleResource(bundleConfig), metav1.CreateOptions{})
		require.Nil(t, err)
		err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond*50, time.Second, true, func(ctx context.Context) (done bool, err error) {
			_, getErr := controller.supportBundleCollectionLister.Get(tc.bundleConfig.name)
			if getErr == nil {
				return true, nil
			}
			if k8serrors.IsNotFound(getErr) {
				return false, nil
			}
			return false, getErr
		})
		assert.NoError(t, err)
		_, err = controller.createInternalSupportBundleCollection(bundle)
		if tc.expectedError != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedError)
		} else {
			require.NoError(t, err)
			if !tc.expectFailure {
				obj, exists, err := controller.supportBundleCollectionStore.Get(bundle.Name)
				require.NoError(t, err)
				assert.True(t, exists)
				_, exists, err = controller.supportBundleCollectionAppliedToStore.GetByKey(bundle.Name)
				require.NoError(t, err)
				assert.True(t, exists)
				internalBundle, _ := obj.(*types.SupportBundleCollection)
				assert.Equal(t, tc.expectedNodes, internalBundle.NodeNames)
				assert.Equal(t, tc.expectedAuth, internalBundle.Authentication)
			} else {
				updatedBundle, err := testClient.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.TODO(), bundle.Name, metav1.GetOptions{})
				require.NoError(t, err)
				conditions := updatedBundle.Status.Conditions
				assert.True(t, len(conditions) > 0)
				var exists bool
				for _, c := range conditions {
					if c.Type == v1alpha1.CollectionFailure && c.Status == metav1.ConditionTrue {
						exists = true
						break
					}
				}
				assert.True(t, exists)
			}
		}
	}

	// Test update span
	err := testClient.client.CoreV1().Nodes().Delete(context.TODO(), "n3", metav1.DeleteOptions{})
	require.NoError(t, err)
	updatedBundleCollection := generateSupportBundleResource(
		bundleConfig{
			name: "b1",
			nodes: &bundleNodes{
				names:  []string{"n1", "n2"},
				labels: map[string]string{"test": "selected"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: secretNamespace,
		})
	// Wait for data sync between client and nodeLister
	time.Sleep(time.Millisecond * 500)
	_, err = controller.createInternalSupportBundleCollection(updatedBundleCollection)
	assert.NoError(t, err)

	// Test deletion.
	for _, tc := range testCases {
		err = controller.deleteInternalSupportBundleCollection(tc.name)
		require.NoError(t, err)
		_, exists, err := controller.supportBundleCollectionStore.Get(tc.name)
		require.NoError(t, err)
		assert.False(t, exists)
		_, exists, err = controller.supportBundleCollectionAppliedToStore.GetByKey(tc.name)
		require.NoError(t, err)
		assert.False(t, exists)
	}
}

func TestSyncSupportBundleCollection(t *testing.T) {
	coreObjects, crdObjects := prepareTopology()
	expiredDuration, _ := time.ParseDuration("-70m")
	expiredCreateTime := time.Now().Add(expiredDuration)
	testCases := []struct {
		bundleConfig
		created bool
	}{
		{
			bundleConfig: bundleConfig{
				name: "b0",
				nodes: &bundleNodes{
					labels: map[string]string{"test": "selected"},
				},
				authType: v1alpha1.APIKey,
			},
			created: true,
		}, {
			bundleConfig: bundleConfig{
				name: "b1",
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					labels:    map[string]string{"test": "selected"},
				},
				authType: v1alpha1.APIKey,
				conditions: []v1alpha1.SupportBundleCollectionCondition{
					{
						Type:   v1alpha1.CollectionStarted,
						Status: metav1.ConditionTrue,
					},
				},
			},
			created: true,
		}, {
			bundleConfig: bundleConfig{
				name: "b2",
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					names:     []string{"en1"},
				},
				authType: v1alpha1.APIKey,
				conditions: []v1alpha1.SupportBundleCollectionCondition{
					{
						Type:   v1alpha1.CollectionCompleted,
						Status: metav1.ConditionTrue,
					},
				},
			},
			created: false,
		}, {
			bundleConfig: bundleConfig{
				name: "b3",
				nodes: &bundleNodes{
					names: []string{"n1", "n3"},
				},
				authType: v1alpha1.BearerToken,
				conditions: []v1alpha1.SupportBundleCollectionCondition{
					{
						Type:   v1alpha1.CollectionCompleted,
						Status: metav1.ConditionTrue,
					},
					{
						Type:   v1alpha1.CollectionFailure,
						Status: metav1.ConditionTrue,
					},
				},
			},
			created: false,
		}, {
			bundleConfig: bundleConfig{
				name: "b4",
				externalNodes: &bundleExternalNodes{
					namespace: "ns2",
					names:     []string{"en4"},
				},
				authType: v1alpha1.APIKey,
				conditions: []v1alpha1.SupportBundleCollectionCondition{
					{
						Type:   v1alpha1.CollectionCompleted,
						Status: metav1.ConditionTrue,
					},
				},
				createTime: &expiredCreateTime,
			},
		}, {
			bundleConfig: bundleConfig{
				name: "b5",
				externalNodes: &bundleExternalNodes{
					namespace: "ns1",
					names:     []string{"en5"},
				},
				authType: v1alpha1.APIKey,
			},
			created: false,
		},
	}

	for _, tc := range testCases {
		secretName := secretWithAPIKey
		if tc.bundleConfig.authType == v1alpha1.BearerToken {
			secretName = secretWithToken
		}
		bundleConfig := tc.bundleConfig
		bundleConfig.secretName = secretName
		bundleConfig.secretNamespace = secretNamespace
		bundleCollection := generateSupportBundleResource(bundleConfig)
		crdObjects = append(crdObjects, bundleCollection)
	}

	testClient := newTestClient(coreObjects, crdObjects)
	controller := newController(testClient)
	stopCh := make(chan struct{})
	testClient.start(stopCh)

	testClient.waitForSync(stopCh)

	go controller.worker()

	for _, tc := range testCases {
		err := wait.PollUntilContextTimeout(context.Background(), time.Millisecond*100, time.Second, true, func(ctx context.Context) (done bool, err error) {
			_, exists, err := controller.supportBundleCollectionStore.Get(tc.bundleConfig.name)
			if err != nil {
				return false, err
			}
			if exists != tc.created {
				return false, nil
			}
			return true, nil
		})
		assert.NoError(t, err)
	}

}
func TestAddInternalSupportBundleCollection(t *testing.T) {
	testClient := newTestClient(nil, nil)
	controller := newController(testClient)

	authentication := &controlplane.BundleServerAuthConfiguration{
		APIKey: "bundle_api_key",
	}
	expiredAt := metav1.NewTime(time.Now().Add(time.Minute * 60))

	verifyBundleCollectionAppliedToStoreIndexers := func(indexer, indexerKey, collectionName string) {
		selectedSupportBundleCollections, err := controller.supportBundleCollectionAppliedToStore.ByIndex(indexer, indexerKey)
		assert.NoError(t, err)
		for _, obj := range selectedSupportBundleCollections {
			bundleAppliedTo := obj.(*supportBundleCollectionAppliedTo)
			if bundleAppliedTo.name == collectionName {
				return
			}
		}
		t.Errorf("unabled to find supportBundleCollectionAppliedTo with name %s", collectionName)
	}
	for _, tc := range []struct {
		name                    string
		nodes                   *bundleNodes
		externalNodes           *bundleExternalNodes
		nodeSpan                sets.Set[string]
		processingNodes         bool
		processingExternalNodes bool
	}{
		{
			name:            "b1",
			nodes:           &bundleNodes{},
			nodeSpan:        sets.New[string]("n1", "n2", "n3", "n4"),
			processingNodes: true,
		}, {
			name:                    "b2",
			externalNodes:           &bundleExternalNodes{namespace: "ns1"},
			nodeSpan:                sets.New[string]("en1", "en2", "en3", "en4"),
			processingExternalNodes: true,
		},
	} {
		bundleConfig := bundleConfig{
			name:            tc.name,
			nodes:           tc.nodes,
			externalNodes:   tc.externalNodes,
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: "default",
		}
		bundleCollection := generateSupportBundleResource(bundleConfig)
		controller.addInternalSupportBundleCollection(bundleCollection, tc.nodeSpan, authentication, expiredAt)
		_, exists, err := controller.supportBundleCollectionStore.Get(tc.name)
		assert.NoError(t, err)
		assert.True(t, exists)
		_, exists, err = controller.supportBundleCollectionAppliedToStore.GetByKey(tc.name)
		assert.NoError(t, err)
		assert.True(t, exists)
		if tc.processingNodes {
			verifyBundleCollectionAppliedToStoreIndexers(processingNodesIndex, processingNodesIndexValue, tc.name)
		}
		if tc.processingExternalNodes {
			verifyBundleCollectionAppliedToStoreIndexers(processingExternalNodesIndex, tc.externalNodes.namespace, tc.name)
		}
	}
}

func TestIsCollectionAvailable(t *testing.T) {
	testClient := newTestClient(nil, nil)
	controller := newController(testClient)
	// prepare test SupportBundleCollections
	var testBundleCollections []*v1alpha1.SupportBundleCollection
	for _, bc := range []bundleConfig{
		{
			name: "b3",
			nodes: &bundleNodes{
				names:  []string{"n3", "n4"},
				labels: map[string]string{"test": "not-selected"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: "ns1",
		}, {
			name: "b4",
			externalNodes: &bundleExternalNodes{
				namespace: "ns1",
				names:     []string{"n3", "n4"},
				labels:    map[string]string{"test": "not-selected"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: "ns1",
		}, {
			name: "b5",
			externalNodes: &bundleExternalNodes{
				namespace: "ns2",
				names:     []string{"n3", "n4"},
				labels:    map[string]string{"test": "selected"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: "ns1",
		}, {
			name: "b6",
			nodes: &bundleNodes{
				names:  []string{"n3", "n4"},
				labels: map[string]string{"test": "not-selected"},
			},
			externalNodes: &bundleExternalNodes{
				namespace: "ns2",
				names:     []string{"n3", "n4"},
				labels:    map[string]string{"test": "selected"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: "ns1",
		},
		{
			name: "b7",
			nodes: &bundleNodes{
				names:  []string{"n1", "n2"},
				labels: map[string]string{"test": "selected"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: "ns1",
		},
		{
			name: "b8",
			externalNodes: &bundleExternalNodes{
				namespace: "ns1",
				names:     []string{"n3", "n4"},
				labels:    map[string]string{"test": "not-selected"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "s1",
			secretNamespace: "ns1",
		},
	} {
		testBundleCollections = append(testBundleCollections, generateSupportBundleResource(bc))
	}

	processingCollections := map[string]*supportBundleCollectionAppliedTo{
		"b0": {
			name:         "b0",
			processNodes: true,
		},
		"b1": {
			name:        "b1",
			enNamespace: "ns1",
		},
		"b2": {
			name:         "b2",
			processNodes: true,
			enNamespace:  "ns1",
		},
	}

	for _, tc := range []struct {
		existedAppliedTo       string
		availableCollections   sets.Set[string]
		unAvailableCollections sets.Set[string]
	}{
		{
			existedAppliedTo:       "",
			availableCollections:   sets.New[string]("b3", "b4", "b5", "b6", "b7", "b8"),
			unAvailableCollections: sets.New[string](),
		},
		{
			existedAppliedTo:       "b0",
			availableCollections:   sets.New[string]("b4", "b5", "b8"),
			unAvailableCollections: sets.New[string]("b3", "b6", "b7"),
		},
		{
			existedAppliedTo:       "b1",
			availableCollections:   sets.New[string]("b3", "b5", "b6", "b7"),
			unAvailableCollections: sets.New[string]("b4", "b8"),
		},
		{
			existedAppliedTo:       "b2",
			availableCollections:   sets.New[string]("b5"),
			unAvailableCollections: sets.New[string]("b3", "b4", "b6", "b7", "b8"),
		},
	} {
		appliedTo, exists := processingCollections[tc.existedAppliedTo]
		if exists {
			err := controller.supportBundleCollectionAppliedToStore.Add(appliedTo)
			assert.NoError(t, err)
		}
		availableCollections := sets.New[string]()
		unAvailableCollections := sets.New[string]()
		for _, collection := range testBundleCollections {
			ok := controller.isCollectionAvailable(collection)
			if ok {
				availableCollections.Insert(collection.Name)
			} else {
				unAvailableCollections.Insert(collection.Name)
			}
		}
		assert.Equal(t, tc.availableCollections, availableCollections)
		assert.Equal(t, tc.unAvailableCollections, unAvailableCollections)
		if exists {
			err := controller.supportBundleCollectionAppliedToStore.Delete(appliedTo)
			assert.NoError(t, err)
		}
	}
}

func TestSupportBundleCollectionStatusEqual(t *testing.T) {
	for _, tc := range []struct {
		oldStatus v1alpha1.SupportBundleCollectionStatus
		newStatus v1alpha1.SupportBundleCollectionStatus
		equal     bool
	}{
		{
			oldStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			newStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 5,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			equal: false,
		},
		{
			oldStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			newStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue},
				},
			},
			equal: false,
		},
		{
			oldStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue},
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
				},
			},
			newStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue},
				},
			},
			equal: true,
		}, {
			oldStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Now())},
				},
			},
			newStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Now().Add(time.Minute))},
				},
			},
			equal: true,
		}, {
			oldStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Now())},
				},
			},
			newStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   100,
				CollectedNodes: 4,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionFalse, LastTransitionTime: metav1.NewTime(time.Now())},
				},
			},
			equal: false,
		},
	} {
		for _, conditions := range [][]v1alpha1.SupportBundleCollectionCondition{
			tc.oldStatus.Conditions, tc.newStatus.Conditions,
		} {
			sort.Slice(conditions, func(i, j int) bool {
				a := conditions[i]
				b := conditions[j]
				if a.Type == b.Type {
					return a.Status < b.Status
				}
				return a.Type < b.Type
			})
		}

		equals := supportBundleCollectionStatusEqual(tc.oldStatus, tc.newStatus)
		assert.Equal(t, tc.equal, equals)
	}
}

func TestUpdateSupportBundleCollectionStatus(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		existingCollection *v1alpha1.SupportBundleCollection
		updateStatus       *v1alpha1.SupportBundleCollectionStatus
		expectedStatus     v1alpha1.SupportBundleCollectionStatus
	}{
		{
			existingCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "b1",
				},
			},
			updateStatus: &v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 0,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
				},
			},
			expectedStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 0,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
				},
			},
		},
		{
			existingCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "b1",
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionFalse, LastTransitionTime: metav1.NewTime(now)},
					},
				},
			},
			updateStatus: &v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 0,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second))},
				},
			},
			expectedStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 0,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second))},
				},
			},
		},
		{
			existingCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "b1",
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					DesiredNodes:   10,
					CollectedNodes: 0,
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					},
				},
			},
			updateStatus: &v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 1,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
				},
			},
			expectedStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 1,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
				},
			},
		},
		{
			existingCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "b1",
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					DesiredNodes:   10,
					CollectedNodes: 1,
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					},
				},
			},
			updateStatus: &v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 5,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
				},
			},
			expectedStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 5,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
				},
			},
		},
		{
			existingCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "b1",
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					DesiredNodes:   10,
					CollectedNodes: 5,
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
						{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
					},
				},
			},
			updateStatus: &v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 8,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
					{Type: v1alpha1.CollectionFailure, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20)), Reason: string(metav1.StatusReasonInternalError), Message: "Agent error"},
					{Type: v1alpha1.CollectionCompleted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20))},
				},
			},
			expectedStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 8,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
					{Type: v1alpha1.CollectionFailure, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20)), Reason: string(metav1.StatusReasonInternalError), Message: "Agent error"},
					{Type: v1alpha1.CollectionCompleted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20))},
				},
			},
		},
		{
			existingCollection: &v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "b1",
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					DesiredNodes:   10,
					CollectedNodes: 8,
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
						{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
					},
				},
			},
			updateStatus: &v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 10,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
					{Type: v1alpha1.CollectionFailure, Status: metav1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20))},
					{Type: v1alpha1.CollectionCompleted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20))},
				},
			},
			expectedStatus: v1alpha1.SupportBundleCollectionStatus{
				DesiredNodes:   10,
				CollectedNodes: 10,
				Conditions: []v1alpha1.SupportBundleCollectionCondition{
					{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
					{Type: v1alpha1.BundleCollected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 10))},
					{Type: v1alpha1.CollectionFailure, Status: metav1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20))},
					{Type: v1alpha1.CollectionCompleted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(time.Second * 20))},
				},
			},
		},
	} {
		testClient := newTestClient(nil, []runtime.Object{tc.existingCollection})
		controller := newController(testClient)
		stopCh := make(chan struct{})
		testClient.start(stopCh)
		testClient.waitForSync(stopCh)
		collectionName := tc.existingCollection.Name
		err := controller.updateSupportBundleCollectionStatus(collectionName, tc.updateStatus)
		require.NoError(t, err)
		updatedCollection, err := controller.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.TODO(), collectionName, metav1.GetOptions{})
		require.NoError(t, err)
		for _, conditions := range [][]v1alpha1.SupportBundleCollectionCondition{
			tc.expectedStatus.Conditions, updatedCollection.Status.Conditions,
		} {
			sort.Slice(conditions, func(i, j int) bool {
				a := conditions[i]
				b := conditions[j]
				if a.Type == b.Type {
					return a.Status < b.Status
				}
				return a.Type < b.Type
			})
		}
		assert.True(t, supportBundleCollectionStatusEqual(tc.expectedStatus, updatedCollection.Status))
	}
}

func TestUpdateStatus(t *testing.T) {
	var controller *Controller
	namespace := "ns1"
	getSpan := func(nodesCount int) []string {
		nodes := make([]string, nodesCount)
		for i := 0; i < nodesCount; i++ {
			nodeKey := fmt.Sprintf("n%d", i)
			if i%2 == 0 {
				nodeKey = k8s.NamespacedName(namespace, nodeKey)
			}
			nodes[i] = nodeKey
		}
		return nodes
	}
	prepareController := func(collectionName string, desiredNodes int) {
		testClient := newTestClient(nil, []runtime.Object{
			&v1alpha1.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{Name: collectionName},
				Spec: v1alpha1.SupportBundleCollectionSpec{
					FileServer: v1alpha1.BundleFileServer{
						URL: "sftp://1.1.1.1/supportbundles/upload",
					},
					ExpirationMinutes: 60,
					SinceTime:         "2h",
				},
				Status: v1alpha1.SupportBundleCollectionStatus{
					DesiredNodes:   int32(desiredNodes),
					CollectedNodes: 0,
					Conditions: []v1alpha1.SupportBundleCollectionCondition{
						{Type: v1alpha1.CollectionStarted, Status: metav1.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Now())},
					},
				},
			},
		})
		controller = newController(testClient)
		controller.supportBundleCollectionStore.Create(&types.SupportBundleCollection{
			Name: collectionName,
			SpanMeta: types.SpanMeta{
				NodeNames: sets.New[string](getSpan(desiredNodes)...),
			},
		})
		stopCh := make(chan struct{})
		testClient.start(stopCh)
		testClient.waitForSync(stopCh)
	}

	updateStatusFunc := func(collectionName string, nodeStatus controlplane.SupportBundleCollectionNodeStatus) {
		status := &controlplane.SupportBundleCollectionStatus{
			ObjectMeta: metav1.ObjectMeta{
				Name: collectionName,
			},
			Nodes: []controlplane.SupportBundleCollectionNodeStatus{
				nodeStatus,
			},
		}
		err := controller.UpdateStatus(status)
		require.NoError(t, err)
	}

	syncSupportBundleCollection := func() {
		key, _ := controller.queue.Get()
		controller.queue.Done(key)
		err := controller.syncSupportBundleCollection(key.(string))
		assert.NoError(t, err)
	}

	agentReportStatus := func(nodesCount, failedNodes int, collectionName string) {
		for i := 0; i < nodesCount; i++ {
			nodeName := fmt.Sprintf("n%d", i)
			nodeType := controlplane.SupportBundleCollectionNodeTypeNode
			if i%2 == 0 {
				nodeType = controlplane.SupportBundleCollectionNodeTypeExternalNode
			}
			completed := true
			if i < failedNodes {
				completed = false
			}
			nodeStatus := controlplane.SupportBundleCollectionNodeStatus{
				NodeName:  nodeName,
				NodeType:  nodeType,
				Completed: completed,
			}
			if nodeType == controlplane.SupportBundleCollectionNodeTypeExternalNode {
				nodeStatus.NodeNamespace = namespace
			}
			updateStatusFunc(collectionName, nodeStatus)
		}
	}

	updateFailure := func(collectionName, name string, errMessage string) {
		nodeStatus := controlplane.SupportBundleCollectionNodeStatus{
			NodeName:  name,
			NodeType:  controlplane.SupportBundleCollectionNodeTypeNode,
			Completed: false,
			Error:     errMessage,
		}
		updateStatusFunc(collectionName, nodeStatus)
	}

	checkCompletedStatus := func(bundleCollection *v1alpha1.SupportBundleCollection) {
		collectionName := bundleCollection.Name
		assert.True(t, conditionExistsIgnoreLastTransitionTime(bundleCollection.Status.Conditions, v1alpha1.SupportBundleCollectionCondition{
			Type:   v1alpha1.CollectionCompleted,
			Status: metav1.ConditionTrue,
		}))
		assert.Eventually(t, func() bool {
			err := controller.syncSupportBundleCollection(collectionName)
			assert.NoError(t, err)
			_, exists, err := controller.supportBundleCollectionStore.Get(collectionName)
			assert.NoError(t, err)
			return !exists
		}, time.Second, time.Millisecond*10)

		_, exists := controller.statuses[collectionName]
		assert.False(t, exists)
	}

	t.Run("all-agent-succeeded", func(t *testing.T) {
		collectionName := "b1"
		desiredNodes := 5
		prepareController(collectionName, desiredNodes)
		agentReportStatus(desiredNodes, 0, collectionName)
		syncSupportBundleCollection()
		bundleCollection, err := controller.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.Background(), collectionName, metav1.GetOptions{})
		assert.NoError(t, err)
		assert.Equal(t, int32(desiredNodes), bundleCollection.Status.CollectedNodes)
		checkCompletedStatus(bundleCollection)
	})

	t.Run("agent-failure", func(t *testing.T) {
		collectionName := "b2"
		desiredNodes := 6
		prepareController(collectionName, desiredNodes)
		reportedNodes := 5
		agentReportStatus(reportedNodes, 2, collectionName)
		syncSupportBundleCollection()
		bundleCollection, err := controller.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.Background(), collectionName, metav1.GetOptions{})
		assert.NoError(t, err)
		assert.Equal(t, int32(3), bundleCollection.Status.CollectedNodes)
		failureStatus := v1alpha1.SupportBundleCollectionCondition{
			Type:    v1alpha1.CollectionFailure,
			Status:  metav1.ConditionTrue,
			Reason:  string(metav1.StatusReasonInternalError),
			Message: `Failed Agent count: 2, "unknown error":[n1, ns1/n0]`,
		}
		assert.True(t, conditionExistsIgnoreLastTransitionTime(bundleCollection.Status.Conditions, failureStatus))
		// Test merging failure message.
		updateFailure(collectionName, "n5", "agent internal error")
		syncSupportBundleCollection()
		bundleCollection, err = controller.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.Background(), collectionName, metav1.GetOptions{})
		assert.NoError(t, err)
		assert.True(t, conditionExistsIgnoreLastTransitionTime(bundleCollection.Status.Conditions, v1alpha1.SupportBundleCollectionCondition{
			Type:    v1alpha1.CollectionFailure,
			Status:  metav1.ConditionTrue,
			Reason:  string(metav1.StatusReasonInternalError),
			Message: `Failed Agent count: 3, "agent internal error":[n5], "unknown error":[n1, ns1/n0]`,
		}))
		assert.False(t, conditionExistsIgnoreLastTransitionTime(bundleCollection.Status.Conditions, failureStatus))
		assert.True(t, conditionExistsIgnoreLastTransitionTime(bundleCollection.Status.Conditions, v1alpha1.SupportBundleCollectionCondition{
			Type:   v1alpha1.CollectionCompleted,
			Status: metav1.ConditionTrue,
		}))
		checkCompletedStatus(bundleCollection)
	})

	t.Run("unknown-agent-report", func(t *testing.T) {
		collectionName := "b3"
		desiredNodes := 3
		prepareController(collectionName, desiredNodes)
		reportedNodes := 1
		agentReportStatus(reportedNodes, 0, collectionName)
		statusPerNode, _ := controller.statuses[collectionName]
		assert.Equal(t, reportedNodes, len(statusPerNode))
		syncSupportBundleCollection()
		assert.Equal(t, reportedNodes, len(statusPerNode))
		// Test status report from the Agent which is not in the SupportBundleCollection span
		updateStatusFunc(collectionName, controlplane.SupportBundleCollectionNodeStatus{
			NodeName:  "n10",
			NodeType:  controlplane.SupportBundleCollectionNodeTypeNode,
			Completed: true,
		})
		statusPerNode, _ = controller.statuses[collectionName]
		assert.Equal(t, reportedNodes+1, len(statusPerNode))
		syncSupportBundleCollection()
		statusPerNode, _ = controller.statuses[collectionName]
		assert.Equal(t, reportedNodes, len(statusPerNode))
	})

	t.Run("non-existing-collection", func(t *testing.T) {
		// Test UpdateStatus with non-existing SupportBundleCollection
		nonExistCollectionName := "no-existing-collection"
		updateStatusFunc(nonExistCollectionName, controlplane.SupportBundleCollectionNodeStatus{
			NodeName:  "n1",
			NodeType:  "Node",
			Completed: true,
		})
		_, exists := controller.statuses[nonExistCollectionName]
		assert.False(t, exists)
	})
}

func newController(tc *testClient) *Controller {
	nodeInformer := tc.informerFactory.Core().V1().Nodes()
	externalNodeInformer := tc.crdInformerFactory.Crd().V1alpha1().ExternalNodes()
	supportBundleInformer := tc.crdInformerFactory.Crd().V1alpha1().SupportBundleCollections()

	store := bundlecollectionstore.NewSupportBundleCollectionStore()
	fakeController := NewSupportBundleCollectionController(tc.client, tc.crdClient, supportBundleInformer, nodeInformer, externalNodeInformer, store)
	return fakeController
}

func testBundleConfigs() []bundleConfig {
	return []bundleConfig{
		{
			name: "bundle-created",
			nodes: &bundleNodes{
				names: []string{"n1", "n2"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "secret1",
			secretNamespace: "default",
			conditions:      []v1alpha1.SupportBundleCollectionCondition{},
			phase:           pending,
		},
		{
			name: "bundle-started",
			externalNodes: &bundleExternalNodes{
				namespace: "ns2",
				names:     []string{"en1", "en2"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "secret1",
			secretNamespace: "default",
			conditions: []v1alpha1.SupportBundleCollectionCondition{
				{
					Type:   v1alpha1.CollectionStarted,
					Status: metav1.ConditionTrue,
				},
			},
			phase: processing,
		},
		{
			name: "bundle-time-expired",
			nodes: &bundleNodes{
				labels: map[string]string{"app": "bundle-test"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "secret1",
			secretNamespace: "default",
			conditions: []v1alpha1.SupportBundleCollectionCondition{
				{
					Type:   v1alpha1.CollectionStarted,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.CollectionCompleted,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.CollectionFailure,
					Status: metav1.ConditionTrue,
					Reason: string(metav1.StatusReasonExpired),
				},
			},
			phase: completed,
		},
		{
			name: "bundle-failed-start",
			externalNodes: &bundleExternalNodes{
				namespace: "ns4",
				labels:    map[string]string{"app": "bundle-test"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "secret1",
			secretNamespace: "default",
			conditions: []v1alpha1.SupportBundleCollectionCondition{
				{
					Type:   v1alpha1.CollectionStarted,
					Status: metav1.ConditionFalse,
					Reason: string(metav1.StatusReasonConflict),
				},
			},
			phase: pending,
		},
		{
			name: "bundle-partial-success",
			externalNodes: &bundleExternalNodes{
				namespace: "ns5",
				labels:    map[string]string{"app": "bundle-test"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "secret1",
			secretNamespace: "default",
			conditions: []v1alpha1.SupportBundleCollectionCondition{
				{
					Type:   v1alpha1.CollectionStarted,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.BundleCollected,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.CollectionCompleted,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.CollectionFailure,
					Status: metav1.ConditionTrue,
					Reason: "Time is expired",
				},
			},
			phase: completed,
		},
		{
			name: "bundle-success",
			nodes: &bundleNodes{
				names: []string{"n1", "n6"},
			},
			authType:        v1alpha1.APIKey,
			secretName:      "secret1`",
			secretNamespace: "default",
			conditions: []v1alpha1.SupportBundleCollectionCondition{
				{
					Type:   v1alpha1.CollectionStarted,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.BundleCollected,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.CollectionCompleted,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   v1alpha1.CollectionFailure,
					Status: metav1.ConditionFalse,
				},
			},
			phase: completed,
		},
	}
}

func prepareBundleCollections(bundleConfigs []bundleConfig) []runtime.Object {
	bundleCollections := make([]runtime.Object, 0)
	for _, bc := range bundleConfigs {
		collection := generateSupportBundleResource(bc)
		bundleCollections = append(bundleCollections, collection)
	}
	return bundleCollections
}

func generateSupportBundleResource(b bundleConfig) *v1alpha1.SupportBundleCollection {
	bundle := &v1alpha1.SupportBundleCollection{
		ObjectMeta: metav1.ObjectMeta{
			Name:              b.name,
			CreationTimestamp: metav1.NewTime(time.Now()),
		},
		Spec: v1alpha1.SupportBundleCollectionSpec{
			FileServer: v1alpha1.BundleFileServer{
				URL: "https://1.1.1.1:443/supportbundles/upload",
			},
			ExpirationMinutes: 60,
			SinceTime:         "2h",
		},
	}
	if b.createTime != nil {
		bundle.ObjectMeta.CreationTimestamp = metav1.NewTime(*b.createTime)
	}
	if b.nodes != nil {
		bundle.Spec.Nodes = &v1alpha1.BundleNodes{}
		if len(b.nodes.names) > 0 {
			bundle.Spec.Nodes.NodeNames = b.nodes.names
		}
		if len(b.nodes.labels) > 0 {
			bundle.Spec.Nodes.NodeSelector = &metav1.LabelSelector{
				MatchLabels: b.nodes.labels,
			}
		}
	}
	if b.externalNodes != nil {
		en := b.externalNodes
		exNode := &v1alpha1.BundleExternalNodes{
			Namespace: en.namespace,
		}
		if len(en.names) > 0 {
			exNode.NodeNames = en.names
		}
		if len(en.labels) > 0 {
			exNode.NodeSelector = &metav1.LabelSelector{
				MatchLabels: en.labels,
			}
		}
		bundle.Spec.ExternalNodes = exNode
	}
	bundle.Spec.Authentication = v1alpha1.BundleServerAuthConfiguration{
		AuthType: b.authType,
		AuthSecret: &corev1.SecretReference{
			Namespace: b.secretNamespace,
			Name:      b.secretName,
		},
	}
	bundle.Status = v1alpha1.SupportBundleCollectionStatus{
		Conditions: b.conditions,
	}
	return bundle
}

func prepareNodes(nodeConfigs []nodeConfig) []runtime.Object {
	var nodes []runtime.Object
	for _, n := range nodeConfigs {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   n.name,
				Labels: n.labels,
			},
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func prepareExternalNodes(externalNodeConfigs []externalNodeConfig) []runtime.Object {
	externalNodes := make([]runtime.Object, 0)
	for _, en := range externalNodeConfigs {
		externalNode := &v1alpha1.ExternalNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      en.name,
				Namespace: en.namespace,
				Labels:    en.labels,
			},
		}
		externalNodes = append(externalNodes, externalNode)
	}
	return externalNodes
}

func prepareSecrets(ns string, secretConfigs []secretConfig) []*corev1.Secret {
	secrets := make([]*corev1.Secret, 0)
	for _, s := range secretConfigs {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.name,
				Namespace: ns,
			},
			Data: s.data,
		}
		secrets = append(secrets, secret)
	}
	return secrets
}

func prepareTopology() ([]runtime.Object, []runtime.Object) {
	var coreObjects, crdObjects []runtime.Object
	for _, n := range prepareNodes([]nodeConfig{
		{name: "n1"},
		{name: "n2"},
		{name: "n3", labels: map[string]string{"test": "selected"}},
		{name: "n4", labels: map[string]string{"test": "selected"}},
		{name: "n5", labels: map[string]string{"test": "not-selected"}},
	}) {
		coreObjects = append(coreObjects, n)
	}
	for _, en := range prepareExternalNodes([]externalNodeConfig{
		{namespace: "ns1", name: "en1"},
		{namespace: "ns1", name: "en2"},
		{namespace: "ns1", name: "en3", labels: map[string]string{"test": "selected"}},
		{namespace: "ns1", name: "en4", labels: map[string]string{"test": "not-selected"}},
		{namespace: "ns2", name: "en5", labels: map[string]string{"test": "selected"}},
	}) {
		crdObjects = append(crdObjects, en)
	}

	apiKey := []byte(testKeyString)
	token := []byte(testTokenString)
	username := []byte("testUsername")
	pwd := []byte("testPassword")
	for _, s := range prepareSecrets(secretNamespace, []secretConfig{
		{name: secretWithAPIKey, data: map[string][]byte{secretKeyWithAPIKey: apiKey}},
		{name: secretWithToken, data: map[string][]byte{secretKeyWithBearerToken: token}},
		{name: secretWithBasicAuth, data: map[string][]byte{secretKeyWithUsername: username, secretKeyWithPassword: pwd}},
	}) {
		coreObjects = append(coreObjects, s)
	}
	return coreObjects, crdObjects
}

type testClient struct {
	client             kubernetes.Interface
	crdClient          clientset.Interface
	informerFactory    informers.SharedInformerFactory
	crdInformerFactory crdinformers.SharedInformerFactory
}

func newTestClient(coreObjects []runtime.Object, crdObjects []runtime.Object) *testClient {
	client := fake.NewSimpleClientset(coreObjects...)
	crdClient := fakeclientset.NewSimpleClientset(crdObjects...)
	return &testClient{
		client:             client,
		crdClient:          crdClient,
		informerFactory:    informers.NewSharedInformerFactory(client, informerDefaultResync),
		crdInformerFactory: crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync),
	}
}

func (c *testClient) start(stopCh <-chan struct{}) {
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.Start(stopCh)
}

func (c *testClient) waitForSync(stopCh <-chan struct{}) {
	c.informerFactory.WaitForCacheSync(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
}
