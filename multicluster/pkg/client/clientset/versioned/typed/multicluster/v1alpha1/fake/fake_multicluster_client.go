// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/typed/multicluster/v1alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeMulticlusterV1alpha1 struct {
	*testing.Fake
}

func (c *FakeMulticlusterV1alpha1) ClusterInfoImports(namespace string) v1alpha1.ClusterInfoImportInterface {
	return &FakeClusterInfoImports{c, namespace}
}

func (c *FakeMulticlusterV1alpha1) ClusterProperties(namespace string) v1alpha1.ClusterPropertyInterface {
	return &FakeClusterProperties{c, namespace}
}

func (c *FakeMulticlusterV1alpha1) ClusterSets(namespace string) v1alpha1.ClusterSetInterface {
	return &FakeClusterSets{c, namespace}
}

func (c *FakeMulticlusterV1alpha1) Gateways(namespace string) v1alpha1.GatewayInterface {
	return &FakeGateways{c, namespace}
}

func (c *FakeMulticlusterV1alpha1) LabelIdentities() v1alpha1.LabelIdentityInterface {
	return &FakeLabelIdentities{c}
}

func (c *FakeMulticlusterV1alpha1) MemberClusterAnnounces(namespace string) v1alpha1.MemberClusterAnnounceInterface {
	return &FakeMemberClusterAnnounces{c, namespace}
}

func (c *FakeMulticlusterV1alpha1) ResourceExports(namespace string) v1alpha1.ResourceExportInterface {
	return &FakeResourceExports{c, namespace}
}

func (c *FakeMulticlusterV1alpha1) ResourceImports(namespace string) v1alpha1.ResourceImportInterface {
	return &FakeResourceImports{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeMulticlusterV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
