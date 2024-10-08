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

// FakeGroups implements GroupInterface
type FakeGroups struct {
	Fake *FakeCrdV1beta1
	ns   string
}

var groupsResource = v1beta1.SchemeGroupVersion.WithResource("groups")

var groupsKind = v1beta1.SchemeGroupVersion.WithKind("Group")

// Get takes name of the group, and returns the corresponding group object, and an error if there is any.
func (c *FakeGroups) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.Group, err error) {
	emptyResult := &v1beta1.Group{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(groupsResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.Group), err
}

// List takes label and field selectors, and returns the list of Groups that match those selectors.
func (c *FakeGroups) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.GroupList, err error) {
	emptyResult := &v1beta1.GroupList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(groupsResource, groupsKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.GroupList{ListMeta: obj.(*v1beta1.GroupList).ListMeta}
	for _, item := range obj.(*v1beta1.GroupList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested groups.
func (c *FakeGroups) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(groupsResource, c.ns, opts))

}

// Create takes the representation of a group and creates it.  Returns the server's representation of the group, and an error, if there is any.
func (c *FakeGroups) Create(ctx context.Context, group *v1beta1.Group, opts v1.CreateOptions) (result *v1beta1.Group, err error) {
	emptyResult := &v1beta1.Group{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(groupsResource, c.ns, group, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.Group), err
}

// Update takes the representation of a group and updates it. Returns the server's representation of the group, and an error, if there is any.
func (c *FakeGroups) Update(ctx context.Context, group *v1beta1.Group, opts v1.UpdateOptions) (result *v1beta1.Group, err error) {
	emptyResult := &v1beta1.Group{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(groupsResource, c.ns, group, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.Group), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeGroups) UpdateStatus(ctx context.Context, group *v1beta1.Group, opts v1.UpdateOptions) (result *v1beta1.Group, err error) {
	emptyResult := &v1beta1.Group{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(groupsResource, "status", c.ns, group, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.Group), err
}

// Delete takes name of the group and deletes it. Returns an error if one occurs.
func (c *FakeGroups) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(groupsResource, c.ns, name, opts), &v1beta1.Group{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeGroups) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(groupsResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1beta1.GroupList{})
	return err
}

// Patch applies the patch and returns the patched group.
func (c *FakeGroups) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.Group, err error) {
	emptyResult := &v1beta1.Group{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(groupsResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.Group), err
}
