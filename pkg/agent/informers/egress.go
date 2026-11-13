// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package informers

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdv1beta2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	crdinformersv1beta1 "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta1"
	crdinformersv1beta2 "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta2"
	crdlistersv1beta2 "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/controller/crdconversion"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

type egressInformer struct {
	crdinformersv1beta1.EgressInformer
}

func (i *egressInformer) Lister() crdlistersv1beta2.EgressLister {
	return crdlistersv1beta2.NewEgressLister(i.Informer().GetIndexer())
}

type externalIPPoolInformer struct {
	crdinformersv1beta1.ExternalIPPoolInformer
}

func (i *externalIPPoolInformer) Lister() crdlistersv1beta2.ExternalIPPoolLister {
	return crdlistersv1beta2.NewExternalIPPoolLister(i.Informer().GetIndexer())
}

// NewEgressInformers returns v1beta2 views of informers that list/watch Egresses and ExternalIPPools in v1beta1.
// Call this before starting the factory, and access these caches only through the returned v1beta2 listers.
// This temporary workaround reads the storage version and converts locally so that Agent cache synchronization
// and watch updates do not depend on the conversion webhook being available on antrea-controller.
// Agent single-IP Egress status writes also use v1beta1 until storage migration.
// TODO: Use v1beta2 informers directly once the storage version is switched and existing objects have been migrated.
func NewEgressInformers(factory crdinformers.SharedInformerFactory) (crdinformersv1beta2.EgressInformer, crdinformersv1beta2.ExternalIPPoolInformer, error) {
	egresses := factory.Crd().V1beta1().Egresses()
	pools := factory.Crd().V1beta1().ExternalIPPools()
	trim := k8s.NewTrimmer()
	transform := func(obj interface{}) (interface{}, error) {
		converted, err := convertToV1beta2(obj)
		if err != nil {
			return nil, err
		}
		return trim(converted)
	}
	// SetTransform replaces the factory transform, so retain its metadata trimming after conversion.
	if err := egresses.Informer().SetTransform(transform); err != nil {
		return nil, nil, fmt.Errorf("setting Egress informer transform: %w", err)
	}
	if err := pools.Informer().SetTransform(transform); err != nil {
		return nil, nil, fmt.Errorf("setting ExternalIPPool informer transform: %w", err)
	}
	return &egressInformer{egresses}, &externalIPPoolInformer{pools}, nil
}

func convertToV1beta2(obj interface{}) (interface{}, error) {
	var result runtime.Object
	var kind string
	var convert func(*unstructured.Unstructured, string) (*unstructured.Unstructured, metav1.Status)
	switch obj.(type) {
	case *crdv1beta1.Egress:
		result, kind, convert = &crdv1beta2.Egress{}, "Egress", crdconversion.ConvertEgress
	case *crdv1beta1.ExternalIPPool:
		result, kind, convert = &crdv1beta2.ExternalIPPool{}, "ExternalIPPool", crdconversion.ConvertExternalIPPool
	default:
		// Objects already in the cache may pass through the transform again during resyncs.
		return obj, nil
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, fmt.Errorf("encoding %s for local conversion: %w", kind, err)
	}
	object := &unstructured.Unstructured{Object: raw}
	// Typed list items may have no TypeMeta. Their Go type identifies the source version and kind.
	object.SetAPIVersion(crdv1beta1.SchemeGroupVersion.String())
	object.SetKind(kind)
	converted, status := convert(object, crdv1beta2.SchemeGroupVersion.String())
	if status.Status != metav1.StatusSuccess {
		return nil, fmt.Errorf("converting %s to v1beta2 locally: %s", kind, status.Message)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(converted.Object, result); err != nil {
		return nil, fmt.Errorf("decoding locally converted %s: %w", kind, err)
	}
	return result, nil
}
