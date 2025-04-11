package bgp

import (
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
	v1a1BgpPolicy16BitAsn := &crdv1alpha1.BGPPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "BGPPolicy",
			APIVersion: "crd.antrea.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
		Spec: crdv1alpha1.BGPPolicySpec{
			LocalASN: 65535,
			BGPPeers: []crdv1alpha1.BGPPeer{
				{
					Address: "10.0.0.1",
					Port:    ptr.To(int32(179)),
					ASN:     65535,
				},
			},
		},
	}

	v1a2BgpPolicy16BitAsn := &crdv1alpha2.BGPPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "BGPPolicy",
			APIVersion: "crd.antrea.io/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
		Spec: crdv1alpha2.BGPPolicySpec{
			LocalASN: 65535,
			BGPPeers: []crdv1alpha2.BGPPeer{
				{
					Address: "10.0.0.1",
					Port:    ptr.To(int32(179)),
					ASN:     65535,
				},
			},
		},
	}

	v1a1BgpPolicy32BitLocalAsn := &crdv1alpha1.BGPPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "BGPPolicy",
			APIVersion: "crd.antrea.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
		Spec: crdv1alpha1.BGPPolicySpec{
			LocalASN: -94967296,
			BGPPeers: []crdv1alpha1.BGPPeer{
				{
					Address: "10.0.0.1",
					Port:    ptr.To(int32(179)),
					ASN:     65535,
				},
			},
		},
	}

	v1a2BgpPolicy32BitLocalAsn := &crdv1alpha2.BGPPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "BGPPolicy",
			APIVersion: "crd.antrea.io/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
		Spec: crdv1alpha2.BGPPolicySpec{
			LocalASN: 4200000000,
			BGPPeers: []crdv1alpha2.BGPPeer{
				{
					Address: "10.0.0.1",
					Port:    ptr.To(int32(179)),
					ASN:     65535,
				},
			},
		},
	}

	v1a1BgpPolicy32BitPeerAsn := &crdv1alpha1.BGPPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "BGPPolicy",
			APIVersion: "crd.antrea.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
		Spec: crdv1alpha1.BGPPolicySpec{
			LocalASN: 65535,
			BGPPeers: []crdv1alpha1.BGPPeer{
				{
					Address: "10.0.0.1",
					Port:    ptr.To(int32(179)),
					ASN:     -94967296,
				},
			},
		},
	}

	v1a2BgpPolicy32BitPeerAsn := &crdv1alpha2.BGPPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "BGPPolicy",
			APIVersion: "crd.antrea.io/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy",
		},
		Spec: crdv1alpha2.BGPPolicySpec{
			LocalASN: 65535,
			BGPPeers: []crdv1alpha2.BGPPeer{
				{
					Address: "10.0.0.1",
					Port:    ptr.To(int32(179)),
					ASN:     4200000000,
				},
			},
		},
	}

	cases := []struct {
		name            string
		status          metav1.Status
		inputBgpPolicy  interface{}
		toVersion       string
		outputBgpPolicy interface{}
	}{
		{
			name:            "Convert v1alpha1 BGPPolicy to v1alpha2 BGPPolicy should succeed",
			inputBgpPolicy:  v1a1BgpPolicy16BitAsn,
			toVersion:       "crd.antrea.io/v1alpha2",
			outputBgpPolicy: v1a2BgpPolicy16BitAsn,
			status:          metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:            "Convert v1alpha2 BGPPolicy with 16-bit ASN numbers to v1alpha1 BGPPolicy should succeed",
			inputBgpPolicy:  v1a2BgpPolicy16BitAsn,
			toVersion:       "crd.antrea.io/v1alpha1",
			outputBgpPolicy: v1a1BgpPolicy16BitAsn,
			status:          metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:            "Convert v1alpha2 BGPPolicy with 32-bit localASN to v1alpha1 localAsn should succeed",
			inputBgpPolicy:  v1a2BgpPolicy32BitLocalAsn,
			toVersion:       "crd.antrea.io/v1alpha1",
			outputBgpPolicy: v1a1BgpPolicy32BitLocalAsn,
			status:          metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:            "Convert v1alpha2 BGPPolicy with 32-bit peer asn to v1alpha1 BGPPolicy should succeed",
			inputBgpPolicy:  v1a2BgpPolicy32BitPeerAsn,
			toVersion:       "crd.antrea.io/v1alpha1",
			outputBgpPolicy: v1a1BgpPolicy32BitPeerAsn,
			status:          metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:            "Convert v1alpha1 BGPPolicy with 32-bit localASN to v1alpha2 should succeed",
			inputBgpPolicy:  v1a1BgpPolicy32BitLocalAsn,
			toVersion:       "crd.antrea.io/v1alpha2",
			outputBgpPolicy: v1a2BgpPolicy32BitLocalAsn,
			status:          metav1.Status{Status: metav1.StatusSuccess},
		},
		{
			name:            "Convert v1alpha1 BGPPolicy with 32-bit peer asn to v1alpha2 should succeed",
			inputBgpPolicy:  v1a1BgpPolicy32BitPeerAsn,
			toVersion:       "crd.antrea.io/v1alpha2",
			outputBgpPolicy: v1a2BgpPolicy32BitPeerAsn,
			status:          metav1.Status{Status: metav1.StatusSuccess},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputUnstructured := &unstructured.Unstructured{}
			outputUnstructured := &unstructured.Unstructured{}

			inputJson, err := json.Marshal(tc.inputBgpPolicy)
			assert.NoError(t, err)
			err = inputUnstructured.UnmarshalJSON(inputJson)
			assert.NoError(t, err)

			if tc.outputBgpPolicy != nil {
				outputJson, err := json.Marshal(tc.outputBgpPolicy)
				assert.NoError(t, err)
				err = outputUnstructured.UnmarshalJSON(outputJson)
				assert.NoError(t, err)
			}

			convertedBgpPolicy, status := ConvertBgpPolicy(inputUnstructured, tc.toVersion)
			assert.Equal(t, tc.status, status)
			if status.Status == metav1.StatusSuccess {
				assert.Equal(t, outputUnstructured.Object["spec"], convertedBgpPolicy.Object["spec"])
			}
		})
	}
}
