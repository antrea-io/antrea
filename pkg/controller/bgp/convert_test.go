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
	createV1a1Policy := func(localASN int32, peerASN int32, confederationID int32, confederationMemberASNs []int32) *crdv1alpha1.BGPPolicy {
		res := &crdv1alpha1.BGPPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "BGPPolicy",
				APIVersion: "crd.antrea.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy",
			},
			Spec: crdv1alpha1.BGPPolicySpec{
				LocalASN: localASN,
				BGPPeers: []crdv1alpha1.BGPPeer{
					{
						Address: "10.0.0.1",
						Port:    ptr.To(int32(179)),
						ASN:     peerASN,
					},
				},
			},
		}

		if confederationID >= 0 {
			res.Spec.Confederation = &crdv1alpha1.Confederation{
				Identifier: confederationID,
				MemberASNs: confederationMemberASNs,
			}
		}

		return res
	}

	createV1a2Policy := func(localASN int64, peerASN int64, confederationID int64, confederationMemberASNs []int64) *crdv1alpha2.BGPPolicy {
		res := &crdv1alpha2.BGPPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "BGPPolicy",
				APIVersion: "crd.antrea.io/v1alpha2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy",
			},
			Spec: crdv1alpha2.BGPPolicySpec{
				LocalASN: localASN,
				BGPPeers: []crdv1alpha2.BGPPeer{
					{
						Address: "10.0.0.1",
						Port:    ptr.To(int32(179)),
						ASN:     peerASN,
					},
				},
			},
		}

		if confederationID >= 0 {
			res.Spec.Confederation = &crdv1alpha2.Confederation{
				Identifier: confederationID,
				MemberASNs: confederationMemberASNs,
			}
		}

		return res
	}

	v1a1BgpPolicy16BitASN := createV1a1Policy(65535, 65535, -1, []int32{})
	v1a2BgpPolicy16BitASN := createV1a2Policy(65535, 65535, -1, []int64{})
	v1a2BgpPolicy32BitLocalASN := createV1a2Policy(4200000000, 65535, -1, []int64{})
	v1a2BgpPolicy32BitPeerASN := createV1a2Policy(65535, 4200000000, -1, []int64{})
	v1a1BgpPolicyInvalidLocalASN := createV1a1Policy(0, 65535, -1, []int32{})
	v1a1BgpPolicyInvalidPeerASN := createV1a1Policy(65535, 0, -1, []int32{})
	v1a2BgpPolicyInvalidLocalASN := createV1a2Policy(0, 65535, -1, []int64{})
	v1a2BgpPolicyInvalidPeerASN := createV1a2Policy(65535, 0, -1, []int64{})

	v1a1BgpPolicyConfederation16Bit := createV1a1Policy(65535, 65535, 65535, []int32{65535})
	v1a2BgpPolicyConfederation16Bit := createV1a2Policy(65535, 65535, 65535, []int64{65535})

	v1a1BgpPolicyConfederationInvalidID := createV1a1Policy(65535, 65535, 0, []int32{65535})
	v1a2BgpPolicyConfederationInvalidID := createV1a2Policy(65535, 65535, 0, []int64{65535})
	v1a2BgpPolicyConfederation32bitID := createV1a2Policy(65535, 65535, 4200000000, []int64{65535})

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
			inputBgpPolicy:    v1a1BgpPolicy16BitASN,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicy16BitASN,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha2 BGPPolicy with 16-bit ASN numbers to v1alpha1 BGPPolicy should succeed",
			inputBgpPolicy:    v1a2BgpPolicy16BitASN,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a1BgpPolicy16BitASN,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha2 BGPPolicy with 32-bit localASN to v1alpha1 should fail",
			inputBgpPolicy:    v1a2BgpPolicy32BitLocalASN,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a2BgpPolicyInvalidLocalASN,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha2 BGPPolicy with 32-bit peer asn to v1alpha1 BGPPolicy should fail",
			inputBgpPolicy:    v1a2BgpPolicy32BitPeerASN,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a2BgpPolicyInvalidPeerASN,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha1 BGPPolicy with invalid localASN to v1alpha2 should fail",
			inputBgpPolicy:    v1a1BgpPolicyInvalidLocalASN,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyInvalidLocalASN,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v1alpha1 BGPPolicy with invalid peer asn to v1alpha2 should fail",
			inputBgpPolicy:    v1a1BgpPolicyInvalidPeerASN,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyInvalidPeerASN,
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
			inputBgpPolicy:    v1a1BgpPolicyConfederationInvalidID,
			toVersion:         "crd.antrea.io/v1alpha2",
			expectedBgpPolicy: v1a2BgpPolicyConfederationInvalidID,
			status:            metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:              "Convert v2alpha2 BGPPolicy with 32-bit confederation id to v1alpha1 should fail",
			inputBgpPolicy:    v1a2BgpPolicyConfederation32bitID,
			toVersion:         "crd.antrea.io/v1alpha1",
			expectedBgpPolicy: v1a1BgpPolicyConfederationInvalidID,
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

			convertedBgpPolicy, status := ConvertBGPPolicy(inputUnstructured, tc.toVersion)
			assert.Equal(t, tc.status, status)
			if status.Status == metav1.StatusSuccess {
				convertedBgpPolicy, err = reSerializeBgpPolicy(convertedBgpPolicy)
				assert.NoError(t, err)
				assert.Equal(t, outputUnstructured.Object["spec"], convertedBgpPolicy.Object["spec"])
			}
		})
	}
}
