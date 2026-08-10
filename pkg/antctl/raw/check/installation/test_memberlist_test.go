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
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/v2/pkg/antctl/raw/check"
	"antrea.io/antrea/v2/pkg/apis"
	"antrea.io/antrea/v2/pkg/util/memberlistkeys"
)

const memberlistTestNamespace = "kube-system"

var memberlistTestKey = bytes.Repeat([]byte{0x01}, 32)

func agentConfigMap(conf string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: antreaConfigMapName, Namespace: memberlistTestNamespace},
		Data:       map[string]string{"antrea-agent.conf": conf},
	}
}

func memberlistSecret(data []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: apis.AntreaMemberlistSecretName, Namespace: memberlistTestNamespace},
		Data:       map[string][]byte{apis.MemberlistSecretKeysKey: data},
	}
}

func runMemberlistTest(t *testing.T, objs ...runtime.Object) error {
	t.Helper()
	testContext := &testContext{
		Logger:          check.NewLogger("[memberlist] "),
		client:          fake.NewSimpleClientset(objs...),
		antreaNamespace: memberlistTestNamespace,
	}
	return (&MemberlistTest{}).Run(context.Background(), testContext)
}

func TestMemberlistTestRun(t *testing.T) {
	validKeys := memberlistkeys.FormatKeys([][]byte{memberlistTestKey})

	t.Run("passes with a key and the default configuration", func(t *testing.T) {
		// Both verification options default to true, so an empty configuration is the secure one.
		assert.NoError(t, runMemberlistTest(t, agentConfigMap(""), memberlistSecret(validKeys)))
	})

	t.Run("warns but does not fail when the Secret is missing", func(t *testing.T) {
		assert.NoError(t, runMemberlistTest(t, agentConfigMap("")))
	})

	t.Run("fails when the Secret holds invalid data", func(t *testing.T) {
		err := runMemberlistTest(t, agentConfigMap(""), memberlistSecret([]byte("not-a-key")))
		assert.ErrorContains(t, err, "does not hold a usable key")
	})

	t.Run("fails when the Secret holds no key", func(t *testing.T) {
		err := runMemberlistTest(t, agentConfigMap(""), memberlistSecret(nil))
		assert.ErrorContains(t, err, "does not hold a usable key")
	})

	t.Run("warns but does not fail when verification is disabled", func(t *testing.T) {
		conf := "memberlist:\n  gossipVerifyOutgoing: false\n  gossipVerifyIncoming: false\n"
		assert.NoError(t, runMemberlistTest(t, agentConfigMap(conf), memberlistSecret(validKeys)))
	})

	t.Run("fails when the ConfigMap is missing", func(t *testing.T) {
		err := runMemberlistTest(t, memberlistSecret(validKeys))
		assert.ErrorContains(t, err, "failed to get agent config")
	})
}
