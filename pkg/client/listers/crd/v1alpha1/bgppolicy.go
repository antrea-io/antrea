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

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// BGPPolicyLister helps list BGPPolicies.
// All objects returned here must be treated as read-only.
type BGPPolicyLister interface {
	// List lists all BGPPolicies in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.BGPPolicy, err error)
	// Get retrieves the BGPPolicy from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.BGPPolicy, error)
	BGPPolicyListerExpansion
}

// bGPPolicyLister implements the BGPPolicyLister interface.
type bGPPolicyLister struct {
	indexer cache.Indexer
}

// NewBGPPolicyLister returns a new BGPPolicyLister.
func NewBGPPolicyLister(indexer cache.Indexer) BGPPolicyLister {
	return &bGPPolicyLister{indexer: indexer}
}

// List lists all BGPPolicies in the indexer.
func (s *bGPPolicyLister) List(selector labels.Selector) (ret []*v1alpha1.BGPPolicy, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.BGPPolicy))
	})
	return ret, err
}

// Get retrieves the BGPPolicy from the index for a given name.
func (s *bGPPolicyLister) Get(name string) (*v1alpha1.BGPPolicy, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("bgppolicy"), name)
	}
	return obj.(*v1alpha1.BGPPolicy), nil
}
