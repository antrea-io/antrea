// Copyright 2024 Antrea Authors
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

package ipam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/json"

	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

func TestIPPoolConverter(t *testing.T) {
	v1a2Pool := &crdv1alpha2.IPPool{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IPPool",
			APIVersion: "crd.antrea.io/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pool",
		},
		Spec: crdv1alpha2.IPPoolSpec{
			IPVersion: crdv1alpha2.IPv4,
			IPRanges: []crdv1alpha2.SubnetIPRange{
				{
					IPRange: crdv1alpha2.IPRange{
						Start: "10.2.0.12",
						End:   "10.2.0.20",
					},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "10.2.0.1",
						PrefixLength: 24,
						VLAN:         2,
					},
				},
				{
					IPRange: crdv1alpha2.IPRange{
						Start: "10.2.0.22",
						End:   "10.2.0.30",
					},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "10.2.0.1",
						PrefixLength: 24,
						VLAN:         2,
					},
				},
			},
		},
	}
	v1a2PoolFailedToCov := &crdv1alpha2.IPPool{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IPPool",
			APIVersion: "crd.antrea.io/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pool-failed-to-conv",
		},
		Spec: crdv1alpha2.IPPoolSpec{
			IPVersion: crdv1alpha2.IPv4,
			IPRanges: []crdv1alpha2.SubnetIPRange{
				{
					IPRange: crdv1alpha2.IPRange{
						CIDR: "10.10.1.0/24",
					},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "10.10.1.1",
						PrefixLength: 24,
					},
				},
				{
					IPRange: crdv1alpha2.IPRange{
						CIDR: "10.10.2.0/24",
					},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "10.10.2.1",
						PrefixLength: 24,
					},
				},
			},
		},
	}
	v1b1Pool := &crdv1beta1.IPPool{
		TypeMeta: metav1.TypeMeta{
			Kind:       "IPPool",
			APIVersion: "crd.antrea.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pool",
		},
		Spec: crdv1beta1.IPPoolSpec{
			IPRanges: []crdv1beta1.IPRange{
				{
					Start: "10.2.0.12",
					End:   "10.2.0.20",
				},
				{
					Start: "10.2.0.22",
					End:   "10.2.0.30",
				},
			},
			SubnetInfo: crdv1beta1.SubnetInfo{
				Gateway:      "10.2.0.1",
				PrefixLength: 24,
				VLAN:         2,
			},
		},
	}
	cases := []struct {
		name         string
		inputIPPool  interface{}
		toVersion    string
		outputIPPool interface{}
		status       metav1.Status
	}{
		{
			name:         "Convert v1alpha2 IPPool to v1beta1 IPPool should success",
			inputIPPool:  v1a2Pool,
			toVersion:    "crd.antrea.io/v1beta1",
			outputIPPool: v1b1Pool,
			status:       metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:         "Convert v1beta1 IPPool to v1alpha2 IPPool should success",
			inputIPPool:  v1b1Pool,
			toVersion:    "crd.antrea.io/v1alpha2",
			outputIPPool: v1a2Pool,
			status:       metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:         "Convert v1alpha2 IPPool with different subnet information to v1beta1 IPPool should fail",
			inputIPPool:  v1a2PoolFailedToCov,
			toVersion:    "crd.antrea.io/v1beta1",
			outputIPPool: nil,
			status: metav1.Status{Status: metav1.StatusFailure,
				Message: "failed to convert IPPool from version v1alpha2 to to version v1beta1 because the original ipRanges have different subnet information"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputUnstructured := &unstructured.Unstructured{}
			outputUnstructured := &unstructured.Unstructured{}

			inputJson, err := json.Marshal(tc.inputIPPool)
			assert.NoError(t, err)
			err = inputUnstructured.UnmarshalJSON(inputJson)
			assert.NoError(t, err)
			if tc.outputIPPool != nil {
				outputJson, err := json.Marshal(tc.outputIPPool)
				assert.NoError(t, err)
				err = outputUnstructured.UnmarshalJSON(outputJson)
				assert.NoError(t, err)
			}

			convertedPool, status := ConvertIPPool(inputUnstructured, tc.toVersion)
			assert.Equal(t, tc.status, status)
			if status.Status == metav1.StatusSuccess {
				assert.Equal(t, outputUnstructured.Object["spec"], convertedPool.Object["spec"])
			}
		})
	}
}
