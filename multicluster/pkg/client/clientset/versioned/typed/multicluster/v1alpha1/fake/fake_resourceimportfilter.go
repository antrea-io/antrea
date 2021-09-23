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
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeResourceImportFilters implements ResourceImportFilterInterface
type FakeResourceImportFilters struct {
	Fake *FakeMulticlusterV1alpha1
	ns   string
}

var resourceimportfiltersResource = schema.GroupVersionResource{Group: "multicluster.crd.antrea.io", Version: "v1alpha1", Resource: "resourceimportfilters"}

var resourceimportfiltersKind = schema.GroupVersionKind{Group: "multicluster.crd.antrea.io", Version: "v1alpha1", Kind: "ResourceImportFilter"}

// Get takes name of the resourceImportFilter, and returns the corresponding resourceImportFilter object, and an error if there is any.
func (c *FakeResourceImportFilters) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ResourceImportFilter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(resourceimportfiltersResource, c.ns, name), &v1alpha1.ResourceImportFilter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ResourceImportFilter), err
}

// List takes label and field selectors, and returns the list of ResourceImportFilters that match those selectors.
func (c *FakeResourceImportFilters) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ResourceImportFilterList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(resourceimportfiltersResource, resourceimportfiltersKind, c.ns, opts), &v1alpha1.ResourceImportFilterList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ResourceImportFilterList{ListMeta: obj.(*v1alpha1.ResourceImportFilterList).ListMeta}
	for _, item := range obj.(*v1alpha1.ResourceImportFilterList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested resourceImportFilters.
func (c *FakeResourceImportFilters) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(resourceimportfiltersResource, c.ns, opts))

}

// Create takes the representation of a resourceImportFilter and creates it.  Returns the server's representation of the resourceImportFilter, and an error, if there is any.
func (c *FakeResourceImportFilters) Create(ctx context.Context, resourceImportFilter *v1alpha1.ResourceImportFilter, opts v1.CreateOptions) (result *v1alpha1.ResourceImportFilter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(resourceimportfiltersResource, c.ns, resourceImportFilter), &v1alpha1.ResourceImportFilter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ResourceImportFilter), err
}

// Update takes the representation of a resourceImportFilter and updates it. Returns the server's representation of the resourceImportFilter, and an error, if there is any.
func (c *FakeResourceImportFilters) Update(ctx context.Context, resourceImportFilter *v1alpha1.ResourceImportFilter, opts v1.UpdateOptions) (result *v1alpha1.ResourceImportFilter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(resourceimportfiltersResource, c.ns, resourceImportFilter), &v1alpha1.ResourceImportFilter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ResourceImportFilter), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeResourceImportFilters) UpdateStatus(ctx context.Context, resourceImportFilter *v1alpha1.ResourceImportFilter, opts v1.UpdateOptions) (*v1alpha1.ResourceImportFilter, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(resourceimportfiltersResource, "status", c.ns, resourceImportFilter), &v1alpha1.ResourceImportFilter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ResourceImportFilter), err
}

// Delete takes name of the resourceImportFilter and deletes it. Returns an error if one occurs.
func (c *FakeResourceImportFilters) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(resourceimportfiltersResource, c.ns, name), &v1alpha1.ResourceImportFilter{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeResourceImportFilters) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(resourceimportfiltersResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.ResourceImportFilterList{})
	return err
}

// Patch applies the patch and returns the patched resourceImportFilter.
func (c *FakeResourceImportFilters) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ResourceImportFilter, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(resourceimportfiltersResource, c.ns, name, pt, data, subresources...), &v1alpha1.ResourceImportFilter{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ResourceImportFilter), err
}
