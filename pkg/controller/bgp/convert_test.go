// Copyright 2025 Antrea Authors
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

package bgp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/utils/ptr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

func TestBGPPolicyConverter(t *testing.T) {
	createV1a1Policy := func(localAsn int32, peerAsn int32, confederationId int32, confederationMemberASNs []int32) *crdv1alpha1.BGPPolicy {
		res := &crdv1alpha1.BGPPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "BGPPolicy",
				APIVersion: "crd.antrea.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy",
			},
			Spec: crdv1alpha1.BGPPolicySpec{
				LocalASN: localAsn,
				BGPPeers: []crdv1alpha1.BGPPeer{
					{
						Address: "10.0.0.1",
						Port:    ptr.To(int32(179)),
						ASN:     peerAsn,
					},
				},
			},
		}

		if confederationId >= 0 {
			res.Spec.Confederation = &crdv1alpha1.Confederation{
				Identifier: confederationId,
				MemberASNs: confederationMemberASNs,
			}
		}

		return res
	}

	createV1a2Policy := func(localAsn int64, peerAsn int64, confederationId int64, confederationMemberASNs []int64) *crdv1alpha2.BGPPolicy {
		res := &crdv1alpha2.BGPPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "BGPPolicy",
				APIVersion: "crd.antrea.io/v1alpha2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy",
			},
			Spec: crdv1alpha2.BGPPolicySpec{
				LocalASN: localAsn,
				BGPPeers: []crdv1alpha2.BGPPeer{
					{
						Address: "10.0.0.1",
						Port:    ptr.To(int32(179)),
						ASN:     peerAsn,
					},
				},
			},
		}

		if confederationId >= 0 {
			res.Spec.Confederation = &crdv1alpha2.Confederation{
				Identifier: confederationId,
				MemberASNs: confederationMemberASNs,
			}
		}

		return res
	}

	v1a1BgpPolicy16BitAsn := createV1a1Policy(65535, 65535, -1, []int32{})
	v1a2BgpPolicy16BitAsn := createV1a2Policy(65535, 65535, -1, []int64{})
	v1a2BgpPolicy32BitLocalAsn := createV1a2Policy(4200000000, 65535, -1, []int64{})
	v1a2BgpPolicy32BitPeerAsn := createV1a2Policy(65535, 4200000000, -1, []int64{})
	v1a1BgpPolicyInvalidLocalAsn := createV1a1Policy(0, 65535, -1, []int32{})
	v1a1BgpPolicyInvalidPeerAsn := createV1a1Policy(65535, 0, -1, []int32{})
	v1a2BgpPolicyInvalidLocalAsn := createV1a2Policy(0, 65535, -1, []int64{})
	v1a2BgpPolicyInvalidPeerAsn := createV1a2Policy(65535, 0, -1, []int64{})

	v1a1BgpPolicyConfederation16Bit := createV1a1Policy(65535, 65535, 65535, []int32{65535})
	v1a2BgpPolicyConfederation16Bit := createV1a2Policy(65535, 65535, 65535, []int64{65535})

	v1a1BgpPolicyConfederationInvalidId := createV1a1Policy(65535, 65535, 0, []int32{65535})
	v1a2BgpPolicyConfederationInvalidId := createV1a2Policy(65535, 65535, 0, []int64{65535})
	v1a2BgpPolicyConfederation32bitId := createV1a2Policy(65535, 65535, 4200000000, []int64{65535})

	v1a1BgpPolicyConfederationInvalidMember := createV1a1Policy(65535, 65535, 65535, []int32{0})
	v1a2BgpPolicyConfederationInvalidMember := createV1a2Policy(65535, 65535, 65535, []int64{0})
	v1a2BgpPolicyConfederation32BitMember := createV1a2Policy(65535, 65535, 65535, []int64{4200000000})

	cases := []struct {
		name                string
		status              metav1.Status
		inputBgpPolicy      interface{}
		toVersion           string
		expectInvalidResult bool
		expectInvalidLocal  bool
		expectInvalidPeer   bool
		expectedBgpPolicy   interface{}
	}{
		{
			name:              "Convert v1alpha1 BGPPolicy to v1alpha2 BGPPolicy should succeed",
			inputBgpPolicy:    v1a1BgpPolicy16BitAsn,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicy16BitAsn,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha2 BGPPolicy with 16-bit ASN numbers to v1alpha1 BGPPolicy should succeed",
			inputBgpPolicy:    v1a2BgpPolicy16BitAsn,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a1BgpPolicy16BitAsn,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha2 BGPPolicy with 32-bit localASN to v1alpha1 should fail",
			inputBgpPolicy:    v1a2BgpPolicy32BitLocalAsn,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a2BgpPolicyInvalidLocalAsn,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha2 BGPPolicy with 32-bit peer asn to v1alpha1 BGPPolicy should fail",
			inputBgpPolicy:    v1a2BgpPolicy32BitPeerAsn,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a2BgpPolicyInvalidPeerAsn,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha1 BGPPolicy with invalid localASN to v1alpha2 should fail",
			inputBgpPolicy:    v1a1BgpPolicyInvalidLocalAsn,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyInvalidLocalAsn,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha1 BGPPolicy with invalid peer asn to v1alpha2 should fail",
			inputBgpPolicy:    v1a1BgpPolicyInvalidPeerAsn,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyInvalidPeerAsn,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha1 BGPPolicy with confederation to v1alpha2 should succeed",
			inputBgpPolicy:    v1a1BgpPolicyConfederation16Bit,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyConfederation16Bit,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha2 BGPPolicy with 16bit confederation to v1alpha1 should succeed",
			inputBgpPolicy:    v1a2BgpPolicyConfederation16Bit,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a1BgpPolicyConfederation16Bit,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha1 BGPPolicy with invalid confederation id should fail",
			inputBgpPolicy:    v1a1BgpPolicyConfederationInvalidId,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyConfederationInvalidId,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v2alpha2 BGPPolicy with 32-bit confederation id to v1alpha1 should fail",
			inputBgpPolicy:    v1a2BgpPolicyConfederation32bitId,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a1BgpPolicyConfederationInvalidId,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha1 BGPPolicy with invalid confederation member should fail",
			inputBgpPolicy:    v1a1BgpPolicyConfederationInvalidMember,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyConfederationInvalidMember,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v2alpha2 BGPPolicy with 32-bit confederation member to v1alpha1 should fail",
			inputBgpPolicy:    v1a2BgpPolicyConfederation32BitMember,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a1BgpPolicyConfederationInvalidMember,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
	}

	// This looks a bit silly, but this step is needed to ensure the json
	// we use for comparison is as expected. The unstructured object as returned
	// from the convert function does not adhere to the json serialization hints
	// on the BGPPolicy struct, as it is, well, unstructured.
	// By doing this dance we ensure the unstructured object adheres
	// to the specific json serialization hints for the applicable struct.
	reSerializeBgpPolicy := func(resource *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		var bgpPolicy interface{}

		switch resource.GetAPIVersion() {
		case "crd.antrea.io/v1alpha1":
			bgpPolicy = &crdv1alpha1.BGPPolicy{}
		case "crd.antrea.io/v1alpha2":
			bgpPolicy = &crdv1alpha2.BGPPolicy{}
		default:
			return nil, fmt.Errorf("unexpected API version: %s", resource.GetAPIVersion())
		}

		jsonBytes, err := resource.MarshalJSON()
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(jsonBytes, bgpPolicy)
		if err != nil {
			return nil, err
		}

		jsonBytes, err = json.Marshal(bgpPolicy)
		if err != nil {
			return nil, err
		}

		ret := &unstructured.Unstructured{}
		err = ret.UnmarshalJSON(jsonBytes)
		return ret, err
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputUnstructured := &unstructured.Unstructured{}
			outputUnstructured := &unstructured.Unstructured{}

			inputJson, err := json.Marshal(tc.inputBgpPolicy)
			assert.NoError(t, err)
			err = inputUnstructured.UnmarshalJSON(inputJson)
			assert.NoError(t, err)

			if tc.expectedBgpPolicy != nil {
				expectedJson, err := json.Marshal(tc.expectedBgpPolicy)
				assert.NoError(t, err)
				err = outputUnstructured.UnmarshalJSON(expectedJson)
				assert.NoError(t, err)
			}

			convertedBgpPolicy, status := ConvertBgpPolicy(inputUnstructured, tc.toVersion)
			assert.Equal(t, tc.status, status)
			if status.Status == metav1.StatusSuccess {
				convertedBgpPolicy, err = reSerializeBgpPolicy(convertedBgpPolicy)
				assert.NoError(t, err)
				assert.Equal(t, outputUnstructured.Object["spec"], convertedBgpPolicy.Object["spec"])
			}
		})
	}
}
