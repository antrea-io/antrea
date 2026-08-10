// Copyright 2026 Antrea Authors.
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

package installation

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/v2/pkg/apis"
	"antrea.io/antrea/v2/pkg/util/memberlistkeys"
)

type MemberlistTest struct{}

func init() {
	RegisterTest("memberlist", &MemberlistTest{})
}

// Run verifies that the gossip traffic of the memberlist cluster, which the Egress and
// ServiceExternalIP features rely on, is authenticated and encrypted. This requires a key to be
// present in the antrea-memberlist-keys Secret, and both antrea-agent verification options to be enabled.
//
// The check does not look at whether Egress and ServiceExternalIP are enabled: antrea-controller
// provisions the Secret unconditionally, so we would only be able to skip the check on clusters
// which do not use the memberlist cluster at all, and deciding that from antctl would mean
// duplicating the default value of both feature gates, which changes from one release to the next.
func (t *MemberlistTest) Run(ctx context.Context, testContext *testContext) error {
	agentConf, err := getAgentConfig(ctx, testContext)
	if err != nil {
		return fmt.Errorf("failed to get agent config: %w", err)
	}

	secret, err := testContext.client.CoreV1().Secrets(testContext.antreaNamespace).Get(ctx, apis.AntreaMemberlistSecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Not an error: an antrea-agent which cannot get a key does not create its memberlist
			// instance, so the gossip listener is not even started and the cluster is not exposed.
			// The Egress and ServiceExternalIP features simply do not assign any IP.
			testContext.Warning("%q Secret not found, it is normally created by antrea-controller. The Egress and ServiceExternalIP features cannot assign IPs without it", apis.AntreaMemberlistSecretName)
			return nil
		}
		return fmt.Errorf("failed to get %q Secret: %w", apis.AntreaMemberlistSecretName, err)
	}
	keys, err := memberlistkeys.ParseKeys(secret.Data[apis.MemberlistSecretKeysKey])
	if err != nil {
		return fmt.Errorf("%q Secret does not hold a usable key: %w", apis.AntreaMemberlistSecretName, err)
	}
	testContext.Log("memberlist key is present (%d key(s) configured)", len(keys))

	// Both options default to true, and are only expected to be disabled temporarily, while a
	// cluster is being transitioned to encrypted gossip.
	verifyOutgoing := ptr.Deref(agentConf.Memberlist.GossipVerifyOutgoing, true)
	verifyIncoming := ptr.Deref(agentConf.Memberlist.GossipVerifyIncoming, true)
	if !verifyIncoming {
		testContext.Warning("memberlist gossipVerifyIncoming is disabled: unencrypted gossip traffic is accepted, which means that it is not authenticated")
	}
	if !verifyOutgoing {
		testContext.Warning("memberlist gossipVerifyOutgoing is disabled: the gossip traffic sent by antrea-agent is not encrypted")
	}
	if verifyIncoming && verifyOutgoing {
		testContext.Log("memberlist gossip traffic is authenticated and encrypted")
	}
	return nil
}
