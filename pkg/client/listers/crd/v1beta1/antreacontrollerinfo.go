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

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// AntreaControllerInfoLister helps list AntreaControllerInfos.
// All objects returned here must be treated as read-only.
type AntreaControllerInfoLister interface {
	// List lists all AntreaControllerInfos in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.AntreaControllerInfo, err error)
	// Get retrieves the AntreaControllerInfo from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.AntreaControllerInfo, error)
	AntreaControllerInfoListerExpansion
}

// antreaControllerInfoLister implements the AntreaControllerInfoLister interface.
type antreaControllerInfoLister struct {
	indexer cache.Indexer
}

// NewAntreaControllerInfoLister returns a new AntreaControllerInfoLister.
func NewAntreaControllerInfoLister(indexer cache.Indexer) AntreaControllerInfoLister {
	return &antreaControllerInfoLister{indexer: indexer}
}

// List lists all AntreaControllerInfos in the indexer.
func (s *antreaControllerInfoLister) List(selector labels.Selector) (ret []*v1beta1.AntreaControllerInfo, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.AntreaControllerInfo))
	})
	return ret, err
}

// Get retrieves the AntreaControllerInfo from the index for a given name.
func (s *antreaControllerInfoLister) Get(name string) (*v1beta1.AntreaControllerInfo, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("antreacontrollerinfo"), name)
	}
	return obj.(*v1beta1.AntreaControllerInfo), nil
}
