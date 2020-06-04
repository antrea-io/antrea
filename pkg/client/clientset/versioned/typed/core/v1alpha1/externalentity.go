// Copyright 2020 Antrea Authors
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

package v1alpha1

import (
	"time"

	v1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha1"
	scheme "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ExternalEntitiesGetter has a method to return a ExternalEntityInterface.
// A group's client should implement this interface.
type ExternalEntitiesGetter interface {
	ExternalEntities(namespace string) ExternalEntityInterface
}

// ExternalEntityInterface has methods to work with ExternalEntity resources.
type ExternalEntityInterface interface {
	Create(*v1alpha1.ExternalEntity) (*v1alpha1.ExternalEntity, error)
	Update(*v1alpha1.ExternalEntity) (*v1alpha1.ExternalEntity, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.ExternalEntity, error)
	List(opts v1.ListOptions) (*v1alpha1.ExternalEntityList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ExternalEntity, err error)
	ExternalEntityExpansion
}

// externalEntities implements ExternalEntityInterface
type externalEntities struct {
	client rest.Interface
	ns     string
}

// newExternalEntities returns a ExternalEntities
func newExternalEntities(c *CoreV1alpha1Client, namespace string) *externalEntities {
	return &externalEntities{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the externalEntity, and returns the corresponding externalEntity object, and an error if there is any.
func (c *externalEntities) Get(name string, options v1.GetOptions) (result *v1alpha1.ExternalEntity, err error) {
	result = &v1alpha1.ExternalEntity{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("externalentities").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ExternalEntities that match those selectors.
func (c *externalEntities) List(opts v1.ListOptions) (result *v1alpha1.ExternalEntityList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ExternalEntityList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("externalentities").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested externalEntities.
func (c *externalEntities) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("externalentities").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a externalEntity and creates it.  Returns the server's representation of the externalEntity, and an error, if there is any.
func (c *externalEntities) Create(externalEntity *v1alpha1.ExternalEntity) (result *v1alpha1.ExternalEntity, err error) {
	result = &v1alpha1.ExternalEntity{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("externalentities").
		Body(externalEntity).
		Do().
		Into(result)
	return
}

// Update takes the representation of a externalEntity and updates it. Returns the server's representation of the externalEntity, and an error, if there is any.
func (c *externalEntities) Update(externalEntity *v1alpha1.ExternalEntity) (result *v1alpha1.ExternalEntity, err error) {
	result = &v1alpha1.ExternalEntity{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("externalentities").
		Name(externalEntity.Name).
		Body(externalEntity).
		Do().
		Into(result)
	return
}

// Delete takes name of the externalEntity and deletes it. Returns an error if one occurs.
func (c *externalEntities) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("externalentities").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *externalEntities) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("externalentities").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched externalEntity.
func (c *externalEntities) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ExternalEntity, err error) {
	result = &v1alpha1.ExternalEntity{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("externalentities").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
