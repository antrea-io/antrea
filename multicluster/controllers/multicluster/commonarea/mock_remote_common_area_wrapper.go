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

package commonarea

import (
	"context"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

// fakeRemoteCommonArea is a fake RemoteCommonArea for unit test purpose
type fakeRemoteCommonArea struct {
	client.Client
	ClusterID      common.ClusterID
	LocalClusterID string
	Namespace      string
	status         []mcv1alpha2.ClusterCondition
}

func (c *fakeRemoteCommonArea) GetClusterID() common.ClusterID {
	return c.ClusterID
}

func (c *fakeRemoteCommonArea) GetNamespace() string {
	return c.Namespace
}

func (c *fakeRemoteCommonArea) Start() context.CancelFunc {
	_, stopFunc := context.WithCancel(context.Background())
	return stopFunc
}

func (c *fakeRemoteCommonArea) Stop() {}

func (c *fakeRemoteCommonArea) IsConnected() bool {
	return true
}

func (c *fakeRemoteCommonArea) StartWatching() error {
	return nil
}

func (c *fakeRemoteCommonArea) StopWatching() {
}

func (c *fakeRemoteCommonArea) GetStatus() []mcv1alpha2.ClusterCondition {
	return c.status
}

func (c *fakeRemoteCommonArea) GetLocalClusterID() string {
	return c.LocalClusterID
}

func (c *fakeRemoteCommonArea) AddImportReconciler(reconciler ImportReconciler) {
}

// NewFakeRemoteCommonArea creates a new fakeRemoteCommonArea for unit test purpose only
func NewFakeRemoteCommonArea(fakeClient client.Client, clusterID string, localClusterID string, namespace string, status []mcv1alpha2.ClusterCondition) RemoteCommonArea {
	fakeRemoteCommonArea := &fakeRemoteCommonArea{
		Client:         fakeClient,
		ClusterID:      common.ClusterID(clusterID),
		LocalClusterID: localClusterID,
		Namespace:      namespace,
		status:         status,
	}
	return fakeRemoteCommonArea
}

type funcGetRemoteConfigAndClient func(secretObj *v1.Secret, url string, clusterID common.ClusterID,
	clusterSet *mcv1alpha2.ClusterSet, scheme *runtime.Scheme) (*rest.Config,
	manager.Manager, client.Client, error)

func FuncGetFakeRemoteConfigAndClient(mgr manager.Manager) funcGetRemoteConfigAndClient {
	return func(secretObj *v1.Secret, url string, clusterID common.ClusterID,
		clusterSet *mcv1alpha2.ClusterSet, scheme *runtime.Scheme) (*rest.Config,
		manager.Manager, client.Client, error) {
		_, _, err := getSecretCACrtAndToken(secretObj)
		if err != nil {
			return nil, nil, nil, err
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
		return nil, mgr, fakeClient, nil
	}
}
