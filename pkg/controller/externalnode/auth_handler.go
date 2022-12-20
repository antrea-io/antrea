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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/square/go-jose.v2/jwt"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	externalnodeinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	externalnodelisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	secretIndexName = "namespace-secret"
	legacyIssuer    = "kubernetes/serviceaccount"
)

type claims interface {
	getNamespace() string
	getServiceAccount() string
	getSecretName() string
	getPodName() string
}

type legacyClaims struct {
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
	ServiceAccountUID  string `json:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName         string `json:"kubernetes.io/serviceaccount/secret.name"`
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
}

func (c *legacyClaims) getNamespace() string {
	return c.Namespace
}

func (c *legacyClaims) getServiceAccount() string {
	return c.ServiceAccountName
}

func (c *legacyClaims) getSecretName() string {
	return c.SecretName
}

func (c *legacyClaims) getPodName() string {
	return ""
}

// privateClaims is used for the manually created token on kubernetes Service
type privateClaims struct {
	Kubernetes kubernetes `json:"kubernetes.io,omitempty"`
}

type kubernetes struct {
	Namespace string `json:"namespace,omitempty"`
	Svcacct   ref    `json:"serviceaccount,omitempty"`
	Pod       *ref   `json:"pod,omitempty"`
	Secret    *ref   `json:"secret,omitempty"`
}

func (c *privateClaims) getNamespace() string {
	return c.Kubernetes.Namespace
}

func (c *privateClaims) getServiceAccount() string {
	return c.Kubernetes.Svcacct.Name
}

func (c *privateClaims) getSecretName() string {
	if c.Kubernetes.Secret == nil {
		return ""
	}
	return c.Kubernetes.Secret.Name
}

func (c *privateClaims) getPodName() string {
	if c.Kubernetes.Pod == nil {
		return ""
	}
	return c.Kubernetes.Pod.Name
}

type ref struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type secretTokenAuth struct {
	externalNodeInformer     externalnodeinformers.ExternalNodeInformer
	externalNodeLister       externalnodelisters.ExternalNodeLister
	externalNodeListerSynced cache.InformerSynced
	secretNodeStore          cache.Indexer
}

type secretNodePair struct {
	namespace  string
	secretName string
	nodeName   string
}

func newSecretTokenAuthenticator(externalNodeInformer externalnodeinformers.ExternalNodeInformer) *secretTokenAuth {
	auth := &secretTokenAuth{
		externalNodeInformer:     externalNodeInformer,
		externalNodeLister:       externalNodeInformer.Lister(),
		externalNodeListerSynced: externalNodeInformer.Informer().HasSynced,
		secretNodeStore: cache.NewIndexer(nodeKeyFunc, cache.Indexers{
			secretIndexName: secretIndexFunc,
		}),
	}
	auth.externalNodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    auth.externalNodeAdd,
			UpdateFunc: auth.externalNodeUpdate,
			DeleteFunc: auth.externalNodeDelete,
		},
		resyncPeriod)
	return auth
}

func secretIndexFunc(obj interface{}) ([]string, error) {
	pair := obj.(*secretNodePair)
	if pair.secretName == "" {
		return []string{}, nil
	}
	namespacedName := k8s.NamespacedName(pair.namespace, pair.secretName)
	return []string{namespacedName}, nil
}

func nodeKeyFunc(obj interface{}) (string, error) {
	pair := obj.(*secretNodePair)
	return k8s.NamespacedName(pair.namespace, pair.nodeName), nil
}

func (a *secretTokenAuth) validateToken(queryValues url.Values, tokenData string) ([]string, bool, error) {
	fieldValue := queryValues.Get("fieldSelector")
	if fieldValue == "" {
		return nil, true, nil
	}
	selector, err := fields.ParseSelector(fieldValue)
	if err != nil {
		return nil, false, err
	}
	queriedNodeNames := sets.NewString()
	for _, r := range selector.Requirements() {
		if r.Field == "nodeName" && r.Operator == selection.Equals {
			queriedNodeNames.Insert(r.Value)
		}
	}
	if queriedNodeNames.Len() == 0 {
		// Return true if no nodeName is set in the request.
		return nil, true, nil
	}
	// Parse the claims from the token data. needCheck is false if the token is a service-account-token, which is used
	// in the connection that is initiated from Antrea Agent on a K8s worker Node, or from Nephe Controller.
	claim, needCheck, err := a.parseClaim(tokenData)
	if err != nil {
		return nil, false, fmt.Errorf("invalid token to parse authentication for ExternalNode: %v", err)
	}
	if !needCheck {
		return nil, true, nil
	}

	// Get the ExternalNodes that are configured with the Secret bound with the Token. needCheck is false if the token
	// is not bound to a Secret.
	nodes, needCheck := a.getBoundNodes(claim)
	if !needCheck {
		klog.V(2).InfoS("Token in the request is not binding on Secrets")
		return nil, true, nil
	}

	// Return false if any nodeName used in the request does not match the ExternalNodes that can use the token bound with
	// the Secret provided in.
	for node := range queriedNodeNames {
		if !nodes.Has(node) {
			klog.InfoS("The required Node name is not in the valid list according to the token", "nodeName", node)
			return nil, false, errors.New("not able to request resources on the bound Node with the provided token")
		}
	}

	return nodes.List(), true, nil
}

func (a *secretTokenAuth) parseClaim(tokenData string) (claims, bool, error) {
	parts := strings.Split(tokenData, ".")
	if len(parts) != 3 {
		return nil, false, fmt.Errorf("token format is incorrect")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false, err
	}
	public := &jwt.Claims{}
	if err := json.Unmarshal(payload, public); err != nil {
		return nil, false, err
	}
	if public.Issuer == legacyIssuer {
		private := &legacyClaims{}
		if err := json.Unmarshal(payload, private); err != nil {
			return nil, true, err
		}
		return private, true, nil
	}
	private := &privateClaims{}
	if err := json.Unmarshal(payload, private); err != nil {
		return nil, true, err
	}
	return private, true, nil
}

// getBoundNodes returns the valid ExternalNodes that are allowed to use the token, and a flag that if the token is
// bound to a Secret or not. An empty set is returned when the token is not bound to any Secret, or the bound secret is
// not used by any ExternalNode.
func (a *secretTokenAuth) getBoundNodes(claims claims) (sets.String, bool) {
	pod := claims.getPodName()
	secret := claims.getSecretName()
	if pod != "" {
		klog.V(2).InfoS("Token is bound to Pod object, no need to check the bounded Nodes", "pod", pod)
		return sets.NewString(), false
	}
	if secret == "" {
		klog.V(2).InfoS("Token is not bound to Pod or Secret object, no need to check the bounded Nodes")
		return sets.NewString(), false
	}
	serviceAccount := claims.getServiceAccount()
	// A dedicated Secret with a special name "$serviceaccount-service-account-token" is created for the Service Account
	// to maintain the token. We assume such token is not bound to a single VM, so the following validation on
	// ExternalNode is skipped.
	if secret == strings.Join([]string{serviceAccount, "service-account-token"}, "-") ||
		// The token is auto generated by Kube APIServer (version <=1.24) when creating the ServiceAccount.
		strings.HasPrefix(secret, fmt.Sprintf("%s-token-", serviceAccount)) {
		klog.V(2).InfoS("Token is dedicated for ServiceAccount, no need to check the bounded Nodes")
		return sets.NewString(), false
	}

	namespacedSecret := k8s.NamespacedName(claims.getNamespace(), secret)
	objs, _ := a.secretNodeStore.ByIndex(secretIndexName, namespacedSecret)
	validNodes := sets.NewString()
	for _, obj := range objs {
		pair := obj.(*secretNodePair)
		validNodes.Insert(k8s.NamespacedName(pair.namespace, pair.nodeName))
	}
	return validNodes, true
}

func (a *secretTokenAuth) externalNodeAdd(obj interface{}) {
	en := obj.(*v1alpha1.ExternalNode)
	pair := &secretNodePair{
		namespace:  en.Namespace,
		nodeName:   en.Name,
		secretName: en.Spec.Secret,
	}
	a.secretNodeStore.Add(pair)
}

func (a *secretTokenAuth) externalNodeDelete(obj interface{}) {
	en := obj.(*v1alpha1.ExternalNode)
	pair := &secretNodePair{
		namespace:  en.Namespace,
		nodeName:   en.Name,
		secretName: en.Spec.Secret,
	}
	a.secretNodeStore.Delete(pair)
}

func (a *secretTokenAuth) externalNodeUpdate(old interface{}, new interface{}) {
	oldEN := old.(*v1alpha1.ExternalNode)
	newEN := new.(*v1alpha1.ExternalNode)
	oldSecret := oldEN.Spec.Secret
	newSecret := newEN.Spec.Secret
	if oldSecret == newSecret {
		return
	}
	oldPair := &secretNodePair{
		namespace:  oldEN.Namespace,
		nodeName:   oldEN.Name,
		secretName: oldEN.Spec.Secret,
	}
	a.secretNodeStore.Delete(oldPair)
	newPair := &secretNodePair{
		namespace:  newEN.Namespace,
		nodeName:   newEN.Name,
		secretName: newEN.Spec.Secret,
	}
	a.secretNodeStore.Add(newPair)
}

type externalNodeAuthRequest struct {
	prevAuthenticator authenticator.Request
	secretTokenAuth   *secretTokenAuth
}

func (r *externalNodeAuthRequest) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	token := r.parseToken(req)
	resp, authenticated, err := r.prevAuthenticator.AuthenticateRequest(req)
	if len(token) == 0 || err != nil || !authenticated {
		return resp, authenticated, err
	}
	nodes, authenticated, err := r.secretTokenAuth.validateToken(req.URL.Query(), token)
	if err != nil {
		klog.ErrorS(err, "Failed to validate token on the request")
		return resp, false, err
	}
	if !authenticated {
		klog.InfoS("The request is not authenticated")
		return resp, false, err
	}
	return mergeUserInfoExtras(resp, nodes), true, nil
}

func mergeUserInfoExtras(resp *authenticator.Response, nodes []string) *authenticator.Response {
	userInfo := resp.User
	newUser := &user.DefaultInfo{
		Name:   userInfo.GetName(),
		UID:    userInfo.GetUID(),
		Groups: userInfo.GetGroups(),
	}
	extras := make(map[string][]string)
	for k, v := range userInfo.GetExtra() {
		extras[k] = v
	}
	if len(nodes) > 0 {
		extras["valid-nodes"] = nodes
	}
	if len(extras) > 0 {
		newUser.Extra = extras
	}
	return &authenticator.Response{
		User:      newUser,
		Audiences: resp.Audiences,
	}
}

func (r *externalNodeAuthRequest) parseToken(req *http.Request) string {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 3)
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

func NewAuthenticator(kubeAuth authenticator.Request, externalNodeInformer externalnodeinformers.ExternalNodeInformer) authenticator.Request {
	return &externalNodeAuthRequest{
		prevAuthenticator: kubeAuth,
		secretTokenAuth:   newSecretTokenAuthenticator(externalNodeInformer),
	}
}
