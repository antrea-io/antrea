// Copyright 2023 Antrea Authors
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

package externalnode

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeclientset "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/k8s"
)

type fakeAuthenticator struct {
	response      *authenticator.Response
	authenticated bool
	err           error
}

func (a *fakeAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return a.response, a.authenticated, a.err
}

func TestAuthenAuthenticateRequest(t *testing.T) {
	testUser := &user.DefaultInfo{
		Name: "test1",
		UID:  "12cc944e-291a-4f55-9300-0654622254ac",
		Groups: []string{
			"system:serviceaccount:kube-system:test1",
			"system:serviceaccount",
		},
	}
	prevResponse := &authenticator.Response{
		User: testUser,
		Audiences: []string{
			"https://kubernetes.default.svc.cluster.local",
		},
	}
	// validToken is bound to Secret "secret-for-test"
	// #nosec G101: false positive triggered by variable name which includes "token". The token is only for test.
	validToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQweWxibl9sNG00WC1yemQ1WnYtYUJBUW9kSUhIWlVVeHhHS2hRUXQtSXcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjczNTc2MzM1LCJpYXQiOjE2NzM1NzI3MzUsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInNlY3JldCI6eyJuYW1lIjoic2VjcmV0LWZvci10ZXN0IiwidWlkIjoiYTg1ODVjOGItMThjZS00YWNjLWFiODAtYzRjZWQwYTEyZjJmIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJ0ZXN0MSIsInVpZCI6IjEyY2M5NDRlLTI5MWEtNGY1NS05MzAwLTA2NTQ2MjIyNTRhYyJ9fSwibmJmIjoxNjczNTcyNzM1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06dGVzdDEifQ.bCRre_iPgvkO_NiYVIUwnVbX9yrb2kg0EMouPzGIwFSBdBIGVwlJvfEwF2G20eaiqhfzXdNDZeQQ07Gn-SNohS_KVyjF9a3qup7-2WkTTnl20KUZ0jrFTKGglirDxRAdkR81AvsUCXlCWxmEYHLGxC9cqONaQQYUo2rAhgVFlZYe04RY9l3jvnfamppDEs56hDbpStJHCPAB-So2QDGnIzNWMedo7ZYvIGnZ2Mxf-9el3lFfUBTnvEiYU8nzgcxsmh9ytzUwIc-FNhpp3sVIH4JzVBroY8RjhjF1rZKxG-HBXEqhDWQbNzRJAaqUYy72An9LyAFIjvcr05Z7PbbIfA"
	// podToken is bound to Secret "secret-for-invalid"
	// #nosec G101: false positive triggered by variable name which includes "token". The token is only for test.
	podToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQweWxibl9sNG00WC1yemQ1WnYtYUJBUW9kSUhIWlVVeHhHS2hRUXQtSXcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjczNTg1NDkwLCJpYXQiOjE2NzM1ODE4OTAsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoibmdpbngiLCJ1aWQiOiI0N2NiNGZmZS1mZWFjLTQ3MjMtODQ2MC05NzZjNzZhYzhhOWQifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6InRlc3QxIiwidWlkIjoiMTJjYzk0NGUtMjkxYS00ZjU1LTkzMDAtMDY1NDYyMjI1NGFjIn19LCJuYmYiOjE2NzM1ODE4OTAsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLXN5c3RlbTp0ZXN0MSJ9.ga7TJ3a8L_Jp6Q4brLjpgiZd5LEWxjgUTdajCji9W-QQ3yKAGEZZ2TTgbPI9pewyQaDM0S4Zz9twKFpslZGu5Ik0kKgWCg9Fbn3yGN-MBwRTnpqN2_7az1dPq4KXYozyUrtIeCdZFMYoM3Be0vebmjqCy0L1vvmihL2e_fe_JOAaFSJUK_OKbyeisQf2uD-xYFHBYS-tFqCGFWu08iot8cXsq6R1ufE1BW7PeUdYJD9ep39_Lk6oezgHxlUmXSJZoSR9iavPX_4gVEIvfV9kcjYogf-RRba9rMBDUJpbz6tViZATM2qWH_0t0bqo-FjahNVpIWkzONQReLe5H-Da1g"
	// serviceAccountToken is a token created for ServiceAccount
	// #nosec G101: false positive triggered by variable name which includes "token". The token is only for test.
	serviceAccountToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQweWxibl9sNG00WC1yemQ1WnYtYUJBUW9kSUhIWlVVeHhHS2hRUXQtSXcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhbnRyZWEtYWdlbnQtc2VydmljZS1hY2NvdW50LXRva2VuIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFudHJlYS1hZ2VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImRhN2U0MWY1LTZmMTQtNGU2MC1hZWE0LTJhNDhjYjRlMjVmYiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLXN5c3RlbTphbnRyZWEtYWdlbnQifQ.FnSPpgTE4cJtlW35-NQ-Jl_FKrkDNDcsRaPylhyvCWNPqy2rBSz_KJEmDX1xYMWtUR_dwSJwt8ZRXFyXPzmel8oGX-zs2L9Ba9uWtdOq0ThGtQboixOEea2gR96jYj5QH4f5_ODPRSzxnzfvWlq0U-0mevh2_Rg_cwq8S9_viI3c04Z89vt703xYSmsNmG0wP7ar0ub-HKt4JDhgX23zhIsLqt2SGs0jTbiTWWWm2_RNprw4W8UWoxLeG5wV4VfqcBSurdYx2dr7R7-dPoFYBSCVLJOD7DBu2IjQLrn0efOpctQemJZ69HnhMBgvq0jbMF6xUdcC6qQq2k4BNrAwlA"
	// legacyServiceAccountToken is a token generated in the Secret along with the SA creation, it is the legacy implementation for SA token.
	// #nosec G101: false positive triggered by variable name which includes "token". The token is only for test.
	legacyServiceAccountToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQweWxibl9sNG00WC1yemQ1WnYtYUJBUW9kSUhIWlVVeHhHS2hRUXQtSXcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhbnRyZWEtYWdlbnQtdG9rZW4temp4eHIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiYW50cmVhLWFnZW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiZGE3ZTQxZjUtNmYxNC00ZTYwLWFlYTQtMmE0OGNiNGUyNWZiIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmFudHJlYS1hZ2VudCJ9.hRvfHlDWFsJ-iM4wvSD2XXonvGhnH21HMLAXd77aFiXmnGcecixK87mrGLx8chT1nPQ0rdEZgJCFBxarc4-KRZYMq24hibDXC7UDUUModlhnOfEGAy-nvZf12RNLWW2FRFX9fcWOHsiiYfHKusPGVT69WC3Dkknt5zwrNVfn2N6E4p7Ky5XMPp-iOlq7054PJCZ-qYVbKQ2yCfYMLFXoS1eV25tTTImEoYxzBxBbeKrS2BNkMLuNljSl9bsHJwm7vL2Q299pp_xEGi_TgwC0UfXx-5VUsP3Hf90qeIkKzRcESNPM1K7muzN_kNlQrSUwFoL8sk7UzOMC9aa33y5Xtw"
	for _, tc := range []struct {
		name        string
		token       string
		queryNode   string
		secretNodes []*secretNodePair

		prevAuth bool
		prevErr  error

		expUser user.Info
		expAuth bool
		expErr  error
	}{
		{
			name:      "valid request",
			token:     validToken,
			queryNode: "kube-system/vm1",
			secretNodes: []*secretNodePair{
				{
					namespace:  "kube-system",
					nodeName:   "vm1",
					secretName: "secret-for-test",
				},
			},
			prevAuth: true,
			prevErr:  nil,
			expUser: &user.DefaultInfo{
				Name:   testUser.GetName(),
				UID:    testUser.GetUID(),
				Groups: testUser.GetGroups(),
				Extra:  map[string][]string{"valid-nodes": {"kube-system/vm1"}},
			},
			expAuth: true,
			expErr:  nil,
		},
		{
			name:      "secret bound on multiple nodes",
			token:     validToken,
			queryNode: "kube-system/vm1",
			secretNodes: []*secretNodePair{
				{
					namespace:  "kube-system",
					nodeName:   "vm1",
					secretName: "secret-for-test",
				}, {
					namespace:  "kube-system",
					nodeName:   "vm2",
					secretName: "secret-for-test",
				},
			},
			prevAuth: true,
			prevErr:  nil,
			expUser: &user.DefaultInfo{
				Name:   testUser.GetName(),
				UID:    testUser.GetUID(),
				Groups: testUser.GetGroups(),
				Extra:  map[string][]string{"valid-nodes": {"kube-system/vm1", "kube-system/vm2"}},
			},
			expAuth: true,
			expErr:  nil,
		},
		{
			name:      "failed in previous validation",
			token:     validToken,
			queryNode: "kube-system/vm1",
			secretNodes: []*secretNodePair{
				{
					namespace:  "kube-system",
					nodeName:   "vm1",
					secretName: "secret-for-test",
				},
			},
			prevAuth: false,
			prevErr:  errors.New("invalid token"),
			expUser:  testUser,
			expAuth:  false,
			expErr:   errors.New("invalid token"),
		},
		{
			name:      "invalid parameter in query",
			token:     validToken,
			queryNode: "kube-system/vm2",
			secretNodes: []*secretNodePair{
				{
					namespace:  "kube-system",
					nodeName:   "vm1",
					secretName: "secret-for-test",
				},
			},
			prevAuth: true,
			prevErr:  nil,
			expUser:  prevResponse.User,
			expAuth:  false,
			expErr:   errors.New("not able to request resources on the bound Node with the provided token"),
		},
		{
			name:      "secret bound no nodes",
			token:     validToken,
			queryNode: "kube-system/vm1",
			prevAuth:  true,
			prevErr:   nil,
			expUser:   prevResponse.User,
			expAuth:   false,
			expErr:    errors.New("not able to request resources on the bound Node with the provided token"),
		},
		{
			name:      "valid request with token on pod",
			token:     podToken,
			queryNode: "worker1",
			prevAuth:  true,
			prevErr:   nil,
			expUser: &user.DefaultInfo{
				Name:   testUser.GetName(),
				UID:    testUser.GetUID(),
				Groups: testUser.GetGroups(),
			},
			expAuth: true,
			expErr:  nil,
		},
		{
			name:      "request from service-account token",
			token:     serviceAccountToken,
			queryNode: "worker2",
			prevAuth:  true,
			prevErr:   nil,
			expUser: &user.DefaultInfo{
				Name:   testUser.GetName(),
				UID:    testUser.GetUID(),
				Groups: testUser.GetGroups(),
			},
			expAuth: true,
			expErr:  nil,
		}, {
			name:      "request from legacy service-account token",
			token:     legacyServiceAccountToken,
			queryNode: "worker2",
			prevAuth:  true,
			prevErr:   nil,
			expUser: &user.DefaultInfo{
				Name:   testUser.GetName(),
				UID:    testUser.GetUID(),
				Groups: testUser.GetGroups(),
			},
			expAuth: true,
			expErr:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crdClient := fakeclientset.NewSimpleClientset()
			informerFactory = crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
			externalNodeInformer := informerFactory.Crd().V1alpha1().ExternalNodes()
			fakeAuth := &fakeAuthenticator{prevResponse, tc.prevAuth, tc.prevErr}
			request, err := generateRequest(tc.token, tc.queryNode)
			require.NoError(t, err)
			auth := NewAuthenticator(fakeAuth, externalNodeInformer)
			if len(tc.secretNodes) > 0 {
				for _, s := range tc.secretNodes {
					auth.(*externalNodeAuthRequest).secretTokenAuth.secretNodeStore.Add(s)
				}
			}
			response, authenticated, err := auth.AuthenticateRequest(request)
			assert.Equal(t, tc.expAuth, authenticated)
			assert.Equal(t, tc.expErr, err)
			if tc.expUser != nil {
				assert.NotNil(t, response)
				newUser := response.User
				assert.Equal(t, tc.expUser.GetUID(), newUser.GetUID())
				assert.Equal(t, tc.expUser.GetGroups(), newUser.GetGroups())
				assert.Equal(t, tc.expUser.GetName(), newUser.GetName())
				key := "valid-nodes"
				if expNodes, ok := tc.expUser.GetExtra()[key]; ok {
					actNodes, exist := newUser.GetExtra()[key]
					assert.True(t, exist)
					assert.ElementsMatch(t, expNodes, actNodes)
				}
				assert.Equal(t, tc.expUser.GetExtra(), newUser.GetExtra())
			}
		})
	}
}

func TestExternalNodeEvent(t *testing.T) {
	crdClient := fakeclientset.NewSimpleClientset()
	informerFactory = crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
	externalNodeInformer := informerFactory.Crd().V1alpha1().ExternalNodes()
	auth := newSecretTokenAuthenticator(externalNodeInformer)
	informerFactory.Start(make(chan struct{}))
	secretName := "sec1"
	ns := "ns1"
	enName := "vm1"
	en := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      enName,
		},
		Spec: v1alpha1.ExternalNodeSpec{
			Secret: secretName,
		},
	}
	key := k8s.NamespacedName(ns, enName)
	auth.externalNodeAdd(en)
	namespacedSecret := k8s.NamespacedName(ns, secretName)
	objs, err := auth.secretNodeStore.ByIndex(secretIndexName, namespacedSecret)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(objs))
	assert.Equal(t, enName, objs[0].(*secretNodePair).nodeName)

	updatedSecret := "sec2"
	updatedEn := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      enName,
		},
		Spec: v1alpha1.ExternalNodeSpec{
			Secret: updatedSecret,
		},
	}
	auth.externalNodeUpdate(en, updatedEn)
	obj, exists, err := auth.secretNodeStore.GetByKey(key)
	assert.NoError(t, err)
	assert.True(t, exists)
	secNode := obj.(*secretNodePair)
	assert.Equal(t, updatedSecret, secNode.secretName)
	updatedNamespacedSecret := k8s.NamespacedName(ns, updatedSecret)
	objs, err = auth.secretNodeStore.ByIndex(secretIndexName, updatedNamespacedSecret)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(objs))

	auth.externalNodeDelete(updatedEn)
	_, exists, err = auth.secretNodeStore.GetByKey(key)
	assert.NoError(t, err)
	assert.False(t, exists)
}

func generateRequest(token string, queryNode string) (*http.Request, error) {
	restClient, err := rest.NewRESTClient(&url.URL{Host: "1.1.1.1:443"}, "apis/v1", rest.ClientContentConfig{GroupVersion: corev1.SchemeGroupVersion}, nil, http.DefaultClient)
	if err != nil {
		return nil, err
	}
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", queryNode).String(),
	}
	r := restClient.Get().
		Resource("networkpolicies").
		VersionedParams(&options, scheme.ParameterCodec)
	request, err := http.NewRequest("GET", r.URL().String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	return request, nil
}
