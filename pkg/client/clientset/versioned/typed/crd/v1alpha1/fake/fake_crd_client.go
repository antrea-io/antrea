// Copyright 2022 Antrea Authors
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
	v1alpha1 "antrea.io/antrea/pkg/client/clientset/versioned/typed/crd/v1alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeCrdV1alpha1 struct {
	*testing.Fake
}

func (c *FakeCrdV1alpha1) AccountNodeMappings(namespace string) v1alpha1.AccountNodeMappingInterface {
	return &FakeAccountNodeMappings{c, namespace}
}

func (c *FakeCrdV1alpha1) ClusterNetworkPolicies() v1alpha1.ClusterNetworkPolicyInterface {
	return &FakeClusterNetworkPolicies{c}
}

func (c *FakeCrdV1alpha1) NetworkPolicies(namespace string) v1alpha1.NetworkPolicyInterface {
	return &FakeNetworkPolicies{c, namespace}
}

func (c *FakeCrdV1alpha1) Tiers() v1alpha1.TierInterface {
	return &FakeTiers{c}
}

func (c *FakeCrdV1alpha1) Traceflows() v1alpha1.TraceflowInterface {
	return &FakeTraceflows{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeCrdV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
