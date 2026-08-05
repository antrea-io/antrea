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

package raw

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/v2/pkg/antctl/runtime"
	"antrea.io/antrea/v2/pkg/util/env"
)

const (
	// antctlServiceAccountName is the name of the ServiceAccount which antctl uses to
	// authenticate to the Antrea Agent and Controller APIs. It is created by the standard
	// Antrea manifests, in the same Namespace as the other Antrea resources, and is bound to
	// a ClusterRole which is scoped to the API surface that antctl needs.
	antctlServiceAccountName = "antctl"
	// tokenExpirationSeconds is the lifetime requested for antctl ServiceAccount tokens. 10
	// minutes is the smallest value the kube-apiserver accepts; a shorter one is rejected as
	// invalid. Tokens are refreshed automatically as needed, so there is no reason to ask for
	// more. Note that this is only a request: the kube-apiserver caps the lifetime with
	// --service-account-max-token-expiration, so the granted expiration time is read back from
	// the TokenRequest status rather than assumed.
	tokenExpirationSeconds = int64(600)
	// tokenRefreshMargin is how long before its expiration time a token is considered stale and
	// is renewed. It needs to comfortably exceed the duration of a single API request. It is an
	// upper bound: see newRenewTime for the case of a token granted a short lifetime.
	tokenRefreshMargin = 1 * time.Minute
)

// ResolveAntreaNamespace determines the Namespace in which Antrea is installed, using sources which
// are under the control of the cluster operator. It must never be derived from an object written by
// an Antrea Agent (such as AntreaAgentInfo), as those are not trustworthy for this purpose.
//
// It returns an error when the antrea-agent DaemonSets cannot be looked up, when none is found, or
// when they do not all live in the same Namespace. These are all operator-fixable problems worth
// failing on, and reporting them here is much clearer than the "ServiceAccount not found" which
// would otherwise surface later, when the first token is minted. There is no useful fallback: the
// callers only get this far because an Agent is running, so an unresolved Namespace would either
// fail anyway or authenticate as the ServiceAccount of an unrelated Antrea installation.
//
// Note that finding several DaemonSets is normal and not by itself an error: a cluster with Windows
// Nodes runs both the antrea-agent and antrea-agent-windows DaemonSets, and both carry these
// labels. Only DaemonSets spread across several Namespaces are ambiguous.
func ResolveAntreaNamespace(ctx context.Context, k8sClientset kubernetes.Interface) (string, error) {
	// When antctl runs inside an Antrea Pod, the Namespace is provided by the downward API.
	// Outside of a Pod, POD_NAMESPACE is just an environment variable of the user's shell and
	// says nothing about where Antrea is installed, so it is ignored.
	// Note that no current caller reaches this branch: both "antctl proxy --agent-node" and the
	// remote "antctl supportbundle" only run out-of-cluster. It is kept so that an in-Pod caller
	// added later does not silently fall back to the DaemonSet lookup, which needs a cluster-wide
	// list permission that Antrea Pods do not have.
	if runtime.InPod {
		if namespace := env.GetPodNamespace(); namespace != "" {
			return namespace, nil
		}
	}
	// Otherwise, locate the antrea-agent DaemonSet, which only the cluster operator can create.
	daemonSets, err := k8sClientset.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector:   "app=antrea,component=antrea-agent",
		ResourceVersion: "0",
	})
	if err != nil {
		return "", fmt.Errorf("error when listing antrea-agent DaemonSets to determine the Antrea Namespace: %w", err)
	}
	namespaces := sets.New[string]()
	for i := range daemonSets.Items {
		namespaces.Insert(daemonSets.Items[i].Namespace)
	}
	switch namespaces.Len() {
	case 0:
		return "", fmt.Errorf("no antrea-agent DaemonSet found, cannot determine the Namespace in which Antrea is installed")
	case 1:
		return namespaces.UnsortedList()[0], nil
	default:
		// More than one Antrea installation: we cannot tell which one the Agents belong to.
		return "", fmt.Errorf("antrea-agent DaemonSets found in multiple Namespaces (%s), cannot determine the Namespace in which Antrea is installed", strings.Join(sets.List(namespaces), ", "))
	}
}

// ServiceAccountTokenSource provides short-lived tokens for the antctl ServiceAccount. Tokens are
// minted on demand and cached until they are close to expiring, so that a single source can be
// shared by clients for many Nodes, and so that long-running commands (e.g. "antctl proxy") keep
// working past the lifetime of the first token. It is safe for concurrent use.
//
// These tokens are requested without an audience, so they carry the default kube-apiserver
// audience and remain valid kube-apiserver credentials, limited by the antctl ClusterRole. An
// Agent which captures one can therefore replay it against the kube-apiserver with that
// ClusterRole. Presenting it to an Agent endpoint is a large reduction of the blast radius
// compared to presenting the caller's own credentials, but it is not zero, which is why the
// antctl ClusterRole should be kept as narrow as the antctl commands allow.
//
// Binding the tokens to a dedicated audience (which would make them useless anywhere but the Agent
// API) has been considered and is not workable:
//   - The Agent would have to set APIAudiences on its DelegatingAuthenticationOptions, which
//     applies to every client of the Agent API, not just antctl. Prometheus scrapes the Agent
//     "/metrics" endpoint with a token minted for the default audience; it would stop
//     authenticating. So would older antctl versions talking to a newer Agent.
//   - Adding the dedicated audience to the kube-apiserver --api-audiences would keep those clients
//     working, but the kube-apiserver would then accept tokens bound to that audience as well,
//     making a captured token usable against it again. The binding would buy nothing.
//   - Discovering per-Agent support is unsound here, as the Agent is the party being defended
//     against: falling back after a 401 hands over the unbound token anyway, and advertising
//     support in AntreaAgentInfo lets an Agent declare no support and be given the unbound token.
//
// The only sound variant is a hard cutover gated on a minimum Agent version, along with an
// operator-visible break for Prometheus.
type ServiceAccountTokenSource struct {
	k8sClientset kubernetes.Interface
	namespace    string

	mutex sync.Mutex
	token string
	// renewTime is when the cached token stops being served and a new one is minted. It is
	// always earlier than the token's expiration time, by up to tokenRefreshMargin.
	renewTime time.Time
}

// NewServiceAccountTokenSource returns a token source for the antctl ServiceAccount in the given
// Namespace. No API call is made until a token is actually needed.
func NewServiceAccountTokenSource(k8sClientset kubernetes.Interface, namespace string) *ServiceAccountTokenSource {
	return &ServiceAccountTokenSource{
		k8sClientset: k8sClientset,
		namespace:    namespace,
	}
}

// Token returns a valid token for the antctl ServiceAccount, minting a new one if the cached token
// is missing or about to expire.
func (s *ServiceAccountTokenSource) Token(ctx context.Context) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	now := time.Now()
	if s.token != "" && now.Before(s.renewTime) {
		return s.token, nil
	}
	tokenRequest, err := s.k8sClientset.CoreV1().ServiceAccounts(s.namespace).CreateToken(ctx, antctlServiceAccountName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: ptr.To(tokenExpirationSeconds),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("error when requesting token for ServiceAccount %s/%s: %w", s.namespace, antctlServiceAccountName, err)
	}
	if tokenRequest.Status.Token == "" {
		return "", fmt.Errorf("empty token returned for ServiceAccount %s/%s", s.namespace, antctlServiceAccountName)
	}
	s.token = tokenRequest.Status.Token
	// The kube-apiserver can return an expiration time which differs from the requested one; if
	// it does not report one at all, assume the requested lifetime.
	expirationTime := tokenRequest.Status.ExpirationTimestamp.Time
	if expirationTime.IsZero() {
		expirationTime = now.Add(time.Duration(tokenExpirationSeconds) * time.Second)
	}
	s.renewTime = newRenewTime(now, expirationTime)
	return s.token, nil
}

// newRenewTime returns the time at which a token expiring at expirationTime should be renewed.
// Renewal normally happens tokenRefreshMargin before the expiration time, but the kube-apiserver
// caps token lifetimes with --service-account-max-token-expiration, possibly well below what we
// request. Subtracting a fixed margin from a short lifetime would place the renewal time in the
// past and defeat caching entirely, making every single request mint a new token: on a large
// cluster, "antctl supportbundle" would issue one TokenRequest per Node per request. Never give up
// more than half of the granted lifetime, so that a token is always reused for a while.
func newRenewTime(now time.Time, expirationTime time.Time) time.Time {
	margin := min(tokenRefreshMargin, expirationTime.Sub(now)/2)
	return expirationTime.Add(-margin)
}

// tokenRoundTripper authenticates requests with a token from the given ServiceAccountTokenSource.
// Unlike rest.Config.BearerToken, which is resolved once when the client is built, the token is
// obtained for each request, which allows it to be renewed as it expires.
type tokenRoundTripper struct {
	tokenSource *ServiceAccountTokenSource
	rt          http.RoundTripper
}

func (rt *tokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := rt.tokenSource.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req = utilnet.CloneRequest(req)
	// Any Authorization header already on the request is replaced, and deliberately not
	// preserved as the client-go bearer token round trippers do. All authentication material is
	// stripped from the rest.Config, so nothing in the client can legitimately set one. But
	// "antctl proxy" forwards the headers of the requests it receives verbatim (the
	// upgrade-aware proxy handler only strips hop-by-hop headers), so preserving the header
	// would relay the credentials of a client of the local proxy to the Agent endpoint, which
	// is exactly what this token exists to avoid.
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	// A 401 response is deliberately not turned into a token renewal followed by a retry. The
	// request body has already been consumed at this point and cannot be replayed in general
	// (requests forwarded by "antctl proxy" carry no GetBody), and, more importantly, the party
	// returning the 401 is the one being defended against: an Agent which always answers 401
	// would turn every proxied request into a TokenRequest against the kube-apiserver. The
	// tokenRefreshMargin applied by the token source is what keeps a token from being presented
	// after it expires.
	return rt.rt.RoundTrip(req)
}

func (rt *tokenRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}
