// Copyright 2024 Antrea Authors
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

	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeClusterGroups implements ClusterGroupInterface
type FakeClusterGroups struct {
	Fake *FakeCrdV1beta1
}

var clustergroupsResource = v1beta1.SchemeGroupVersion.WithResource("clustergroups")

var clustergroupsKind = v1beta1.SchemeGroupVersion.WithKind("ClusterGroup")

// Get takes name of the clusterGroup, and returns the corresponding clusterGroup object, and an error if there is any.
func (c *FakeClusterGroups) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.ClusterGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(clustergroupsResource, name), &v1beta1.ClusterGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ClusterGroup), err
}

// List takes label and field selectors, and returns the list of ClusterGroups that match those selectors.
func (c *FakeClusterGroups) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.ClusterGroupList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(clustergroupsResource, clustergroupsKind, opts), &v1beta1.ClusterGroupList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.ClusterGroupList{ListMeta: obj.(*v1beta1.ClusterGroupList).ListMeta}
	for _, item := range obj.(*v1beta1.ClusterGroupList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested clusterGroups.
func (c *FakeClusterGroups) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(clustergroupsResource, opts))
}

// Create takes the representation of a clusterGroup and creates it.  Returns the server's representation of the clusterGroup, and an error, if there is any.
func (c *FakeClusterGroups) Create(ctx context.Context, clusterGroup *v1beta1.ClusterGroup, opts v1.CreateOptions) (result *v1beta1.ClusterGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(clustergroupsResource, clusterGroup), &v1beta1.ClusterGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ClusterGroup), err
}

// Update takes the representation of a clusterGroup and updates it. Returns the server's representation of the clusterGroup, and an error, if there is any.
func (c *FakeClusterGroups) Update(ctx context.Context, clusterGroup *v1beta1.ClusterGroup, opts v1.UpdateOptions) (result *v1beta1.ClusterGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(clustergroupsResource, clusterGroup), &v1beta1.ClusterGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ClusterGroup), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeClusterGroups) UpdateStatus(ctx context.Context, clusterGroup *v1beta1.ClusterGroup, opts v1.UpdateOptions) (*v1beta1.ClusterGroup, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(clustergroupsResource, "status", clusterGroup), &v1beta1.ClusterGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ClusterGroup), err
}

// Delete takes name of the clusterGroup and deletes it. Returns an error if one occurs.
func (c *FakeClusterGroups) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(clustergroupsResource, name, opts), &v1beta1.ClusterGroup{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeClusterGroups) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(clustergroupsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1beta1.ClusterGroupList{})
	return err
}

// Patch applies the patch and returns the patched clusterGroup.
func (c *FakeClusterGroups) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.ClusterGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(clustergroupsResource, name, pt, data, subresources...), &v1beta1.ClusterGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ClusterGroup), err
}
