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

// Package validation provides helpers shared by the CRD admission webhook handlers.
package validation

import (
	"context"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// authorizationTimeout bounds the SubjectAccessReview call made by AuthorizeSecretGet. It must
// stay below the timeoutSeconds configured for the CRD validating webhooks (see the
// ValidatingWebhookConfiguration in
// build/charts/antrea/templates/webhooks/validating/crdvalidator.yaml), so that a slow
// kube-apiserver causes an explicit denial in the caller rather than an admission timeout.
const authorizationTimeout = 3 * time.Second

// AuthorizeSecretGet reports whether the user who issued an admission request is themselves
// authorized to get the given Secret. Webhook handlers use it when the CR under validation makes
// an Antrea component read a Secret with its own privileged ServiceAccount, so that the component
// cannot be used as a confused deputy to read a Secret on behalf of a user who could not read it
// directly.
//
// It returns the SubjectAccessReview status, so that callers can produce a message naming the
// field they are validating: Status.Reason and Status.EvaluationError are meant to be logged, not
// returned to the requester, as they can leak details of the authorization policy to a caller who
// just failed an authorization check. The error returned when the review itself cannot be
// completed is left unwrapped for the same reason: callers add the context identifying the field.
func AuthorizeSecretGet(client kubernetes.Interface, userInfo authnv1.UserInfo, namespace, name string) (*authorizationv1.SubjectAccessReviewStatus, error) {
	var extra map[string]authorizationv1.ExtraValue
	if len(userInfo.Extra) > 0 {
		extra = make(map[string]authorizationv1.ExtraValue, len(userInfo.Extra))
		for k, v := range userInfo.Extra {
			extra[k] = authorizationv1.ExtraValue(v)
		}
	}
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      "get",
				Resource:  "secrets",
				Name:      name,
			},
			User:   userInfo.Username,
			Groups: userInfo.Groups,
			UID:    userInfo.UID,
			Extra:  extra,
		},
	}
	// The admission request's own context is not available here: the validateFunc signature
	// shared by all the CRD webhook handlers does not carry one. authorizationTimeout therefore
	// bounds the call independently, and is kept below the webhook's own timeoutSeconds so that
	// the call cannot outlive the admission request.
	ctx, cancel := context.WithTimeout(context.Background(), authorizationTimeout)
	defer cancel()
	resp, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return &resp.Status, nil
}
