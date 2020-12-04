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

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// AntreaAgentInfoLister helps list AntreaAgentInfos.
type AntreaAgentInfoLister interface {
	// List lists all AntreaAgentInfos in the indexer.
	List(selector labels.Selector) (ret []*v1beta1.AntreaAgentInfo, err error)
	// Get retrieves the AntreaAgentInfo from the index for a given name.
	Get(name string) (*v1beta1.AntreaAgentInfo, error)
	AntreaAgentInfoListerExpansion
}

// antreaAgentInfoLister implements the AntreaAgentInfoLister interface.
type antreaAgentInfoLister struct {
	indexer cache.Indexer
}

// NewAntreaAgentInfoLister returns a new AntreaAgentInfoLister.
func NewAntreaAgentInfoLister(indexer cache.Indexer) AntreaAgentInfoLister {
	return &antreaAgentInfoLister{indexer: indexer}
}

// List lists all AntreaAgentInfos in the indexer.
func (s *antreaAgentInfoLister) List(selector labels.Selector) (ret []*v1beta1.AntreaAgentInfo, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.AntreaAgentInfo))
	})
	return ret, err
}

// Get retrieves the AntreaAgentInfo from the index for a given name.
func (s *antreaAgentInfoLister) Get(name string) (*v1beta1.AntreaAgentInfo, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("antreaagentinfo"), name)
	}
	return obj.(*v1beta1.AntreaAgentInfo), nil
}
