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

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ExternalIPPoolLister helps list ExternalIPPools.
// All objects returned here must be treated as read-only.
type ExternalIPPoolLister interface {
	// List lists all ExternalIPPools in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.ExternalIPPool, err error)
	// Get retrieves the ExternalIPPool from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.ExternalIPPool, error)
	ExternalIPPoolListerExpansion
}

// externalIPPoolLister implements the ExternalIPPoolLister interface.
type externalIPPoolLister struct {
	indexer cache.Indexer
}

// NewExternalIPPoolLister returns a new ExternalIPPoolLister.
func NewExternalIPPoolLister(indexer cache.Indexer) ExternalIPPoolLister {
	return &externalIPPoolLister{indexer: indexer}
}

// List lists all ExternalIPPools in the indexer.
func (s *externalIPPoolLister) List(selector labels.Selector) (ret []*v1beta1.ExternalIPPool, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.ExternalIPPool))
	})
	return ret, err
}

// Get retrieves the ExternalIPPool from the index for a given name.
func (s *externalIPPoolLister) Get(name string) (*v1beta1.ExternalIPPool, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("externalippool"), name)
	}
	return obj.(*v1beta1.ExternalIPPool), nil
}
