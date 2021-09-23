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
// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ResourceImportLister helps list ResourceImports.
// All objects returned here must be treated as read-only.
type ResourceImportLister interface {
	// List lists all ResourceImports in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.ResourceImport, err error)
	// ResourceImports returns an object that can list and get ResourceImports.
	ResourceImports(namespace string) ResourceImportNamespaceLister
	ResourceImportListerExpansion
}

// resourceImportLister implements the ResourceImportLister interface.
type resourceImportLister struct {
	indexer cache.Indexer
}

// NewResourceImportLister returns a new ResourceImportLister.
func NewResourceImportLister(indexer cache.Indexer) ResourceImportLister {
	return &resourceImportLister{indexer: indexer}
}

// List lists all ResourceImports in the indexer.
func (s *resourceImportLister) List(selector labels.Selector) (ret []*v1alpha1.ResourceImport, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.ResourceImport))
	})
	return ret, err
}

// ResourceImports returns an object that can list and get ResourceImports.
func (s *resourceImportLister) ResourceImports(namespace string) ResourceImportNamespaceLister {
	return resourceImportNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ResourceImportNamespaceLister helps list and get ResourceImports.
// All objects returned here must be treated as read-only.
type ResourceImportNamespaceLister interface {
	// List lists all ResourceImports in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.ResourceImport, err error)
	// Get retrieves the ResourceImport from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.ResourceImport, error)
	ResourceImportNamespaceListerExpansion
}

// resourceImportNamespaceLister implements the ResourceImportNamespaceLister
// interface.
type resourceImportNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ResourceImports in the indexer for a given namespace.
func (s resourceImportNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.ResourceImport, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.ResourceImport))
	})
	return ret, err
}

// Get retrieves the ResourceImport from the indexer for a given namespace and name.
func (s resourceImportNamespaceLister) Get(name string) (*v1alpha1.ResourceImport, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("resourceimport"), name)
	}
	return obj.(*v1alpha1.ResourceImport), nil
}
