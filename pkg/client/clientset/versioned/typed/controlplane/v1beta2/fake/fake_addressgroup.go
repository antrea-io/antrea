// Copyright 2021 Antrea Authors
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
	"context"

	v1beta2 "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeAddressGroups implements AddressGroupInterface
type FakeAddressGroups struct {
	Fake *FakeControlplaneV1beta2
}

var addressgroupsResource = schema.GroupVersionResource{Group: "controlplane.antrea.tanzu.vmware.com", Version: "v1beta2", Resource: "addressgroups"}

var addressgroupsKind = schema.GroupVersionKind{Group: "controlplane.antrea.tanzu.vmware.com", Version: "v1beta2", Kind: "AddressGroup"}

// Get takes name of the addressGroup, and returns the corresponding addressGroup object, and an error if there is any.
func (c *FakeAddressGroups) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta2.AddressGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(addressgroupsResource, name), &v1beta2.AddressGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta2.AddressGroup), err
}

// List takes label and field selectors, and returns the list of AddressGroups that match those selectors.
func (c *FakeAddressGroups) List(ctx context.Context, opts v1.ListOptions) (result *v1beta2.AddressGroupList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(addressgroupsResource, addressgroupsKind, opts), &v1beta2.AddressGroupList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta2.AddressGroupList{ListMeta: obj.(*v1beta2.AddressGroupList).ListMeta}
	for _, item := range obj.(*v1beta2.AddressGroupList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested addressGroups.
func (c *FakeAddressGroups) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(addressgroupsResource, opts))
}
