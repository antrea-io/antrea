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

	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

// fakeRemoteCommonArea is a fake RemoteCommonArea for unit test purpose
type fakeRemoteCommonArea struct {
	client.Client
	ClusterID      common.ClusterID
	LocalClusterID string
	Namespace      string
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

func (c *fakeRemoteCommonArea) GetStatus() []multiclusterv1alpha1.ClusterCondition {
	return nil
}

func (c *fakeRemoteCommonArea) GetLocalClusterID() string {
	return c.LocalClusterID
}

// NewFakeRemoteCommonArea creates a new fakeRemoteCommonArea for unit test purpose only
func NewFakeRemoteCommonArea(fakeClient client.Client, clusterID string, localClusterID string, namespace string) RemoteCommonArea {
	fakeRemoteCommonArea := &fakeRemoteCommonArea{
		Client:         fakeClient,
		ClusterID:      common.ClusterID(clusterID),
		LocalClusterID: localClusterID,
		Namespace:      namespace,
	}
	return fakeRemoteCommonArea
}
