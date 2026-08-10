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

package memberlistkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"antrea.io/antrea/v2/pkg/apis"
)

const testNamespace = "kube-system"

var (
	key1 = bytes.Repeat([]byte{0x01}, 32)
	key2 = bytes.Repeat([]byte{0x02}, 32)
)

func encodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func TestParseKeys(t *testing.T) {
	testCases := []struct {
		name         string
		data         string
		expectedKeys [][]byte
		expectedErr  string
	}{
		{
			name:         "single key",
			data:         encodeKey(key1),
			expectedKeys: [][]byte{key1},
		},
		{
			name:         "trailing newline is ignored",
			data:         encodeKey(key1) + "\n",
			expectedKeys: [][]byte{key1},
		},
		{
			name:         "multiple keys, primary first",
			data:         encodeKey(key1) + "\n" + encodeKey(key2) + "\n",
			expectedKeys: [][]byte{key1, key2},
		},
		{
			name:         "surrounding whitespace is trimmed",
			data:         "  " + encodeKey(key1) + "  \n\n",
			expectedKeys: [][]byte{key1},
		},
		{
			name:         "16-byte key is valid",
			data:         encodeKey(bytes.Repeat([]byte{0x03}, 16)),
			expectedKeys: [][]byte{bytes.Repeat([]byte{0x03}, 16)},
		},
		{
			name:        "empty data",
			data:        "",
			expectedErr: "no key found",
		},
		{
			name:        "whitespace only",
			data:        "\n  \n",
			expectedErr: "no key found",
		},
		{
			name:        "not base64",
			data:        "not-valid-base64!!",
			expectedErr: "not valid base64",
		},
		{
			name:        "invalid key length",
			data:        encodeKey([]byte("tooshort")),
			expectedErr: "is invalid",
		},
		{
			// An invalid key must not be skipped silently: using a different primary key than the
			// rest of the cluster would partition the memberlist cluster.
			name:        "one invalid key among valid ones",
			data:        encodeKey(key1) + "\n" + encodeKey([]byte("tooshort")),
			expectedErr: "key at index 1 is invalid",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := ParseKeys([]byte(tc.data))
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedKeys, keys)
		})
	}
}

func TestFormatKeysRoundTrip(t *testing.T) {
	keys := [][]byte{key1, key2}
	parsed, err := ParseKeys(FormatKeys(keys))
	require.NoError(t, err)
	assert.Equal(t, keys, parsed)
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	assert.Len(t, key, apis.MemberlistKeyLen)
	other, err := GenerateKey()
	require.NoError(t, err)
	assert.NotEqual(t, key, other, "generated keys should not be identical")
}

func getSecretKeys(t *testing.T, client *fake.Clientset) [][]byte {
	t.Helper()
	secret, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), apis.AntreaMemberlistSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	keys, err := ParseKeys(secret.Data[apis.MemberlistSecretKeysKey])
	require.NoError(t, err)
	return keys
}

func newSecret(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: apis.AntreaMemberlistSecretName, Namespace: testNamespace},
		Data:       data,
	}
}

func TestEnsureSecret(t *testing.T) {
	ctx := context.Background()

	t.Run("creates the Secret when it does not exist", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		require.NoError(t, NewProvisioner(client, testNamespace).EnsureSecret(ctx))
		keys := getSecretKeys(t, client)
		assert.Len(t, keys, 1)
		assert.Len(t, keys[0], apis.MemberlistKeyLen)
	})

	t.Run("preserves an existing key", func(t *testing.T) {
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key1}),
		}))
		require.NoError(t, NewProvisioner(client, testNamespace).EnsureSecret(ctx))
		assert.Equal(t, [][]byte{key1}, getSecretKeys(t, client))
	})

	t.Run("preserves all the keys of an existing Secret", func(t *testing.T) {
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key1, key2}),
		}))
		require.NoError(t, NewProvisioner(client, testNamespace).EnsureSecret(ctx))
		assert.Equal(t, [][]byte{key1, key2}, getSecretKeys(t, client))
	})

	t.Run("adds a key to a Secret which has none", func(t *testing.T) {
		client := fake.NewSimpleClientset(newSecret(nil))
		require.NoError(t, NewProvisioner(client, testNamespace).EnsureSecret(ctx))
		keys := getSecretKeys(t, client)
		assert.Len(t, keys, 1)
		assert.Len(t, keys[0], apis.MemberlistKeyLen)
	})

	t.Run("keeps other data when adding a key", func(t *testing.T) {
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{"other": []byte("value")}))
		require.NoError(t, NewProvisioner(client, testNamespace).EnsureSecret(ctx))
		secret, err := client.CoreV1().Secrets(testNamespace).Get(ctx, apis.AntreaMemberlistSecretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, []byte("value"), secret.Data["other"])
	})

	t.Run("does not overwrite invalid data", func(t *testing.T) {
		invalid := []byte("this-is-not-a-valid-key")
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: invalid,
		}))
		err := NewProvisioner(client, testNamespace).EnsureSecret(ctx)
		assert.ErrorContains(t, err, "holds invalid data")
		secret, getErr := client.CoreV1().Secrets(testNamespace).Get(ctx, apis.AntreaMemberlistSecretName, metav1.GetOptions{})
		require.NoError(t, getErr)
		assert.Equal(t, invalid, secret.Data[apis.MemberlistSecretKeysKey], "the Secret must be left untouched")
	})

	t.Run("is idempotent", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		p := NewProvisioner(client, testNamespace)
		require.NoError(t, p.EnsureSecret(ctx))
		keys := getSecretKeys(t, client)
		require.NoError(t, p.EnsureSecret(ctx))
		assert.Equal(t, keys, getSecretKeys(t, client), "the key must not be regenerated")
	})

	// Deleting the Secret must not rekey the cluster: the antrea-agents which are already running
	// keep using the key they have, so restoring a different one would partition the cluster.
	t.Run("restores the same key when the Secret is deleted", func(t *testing.T) {
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key1, key2}),
		}))
		p := NewProvisioner(client, testNamespace)
		require.NoError(t, p.EnsureSecret(ctx))
		require.NoError(t, client.CoreV1().Secrets(testNamespace).Delete(ctx, apis.AntreaMemberlistSecretName, metav1.DeleteOptions{}))

		require.NoError(t, p.EnsureSecret(ctx))
		assert.Equal(t, [][]byte{key1, key2}, getSecretKeys(t, client))
	})

	t.Run("restores the same key when the key is removed from the Secret", func(t *testing.T) {
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key1}),
		}))
		p := NewProvisioner(client, testNamespace)
		require.NoError(t, p.EnsureSecret(ctx))
		_, err := client.CoreV1().Secrets(testNamespace).Update(ctx, newSecret(nil), metav1.UpdateOptions{})
		require.NoError(t, err)

		require.NoError(t, p.EnsureSecret(ctx))
		assert.Equal(t, [][]byte{key1}, getSecretKeys(t, client))
	})

	// A key which the user replaced must be adopted, and restored instead of the previous one if
	// the Secret is deleted afterwards.
	t.Run("restores the latest observed key", func(t *testing.T) {
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key1}),
		}))
		p := NewProvisioner(client, testNamespace)
		require.NoError(t, p.EnsureSecret(ctx))
		_, err := client.CoreV1().Secrets(testNamespace).Update(ctx, newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key2}),
		}), metav1.UpdateOptions{})
		require.NoError(t, err)
		require.NoError(t, p.EnsureSecret(ctx))
		require.NoError(t, client.CoreV1().Secrets(testNamespace).Delete(ctx, apis.AntreaMemberlistSecretName, metav1.DeleteOptions{}))

		require.NoError(t, p.EnsureSecret(ctx))
		assert.Equal(t, [][]byte{key2}, getSecretKeys(t, client))
	})

	// A Provisioner which never observed the Secret - antrea-controller was restarted after the
	// deletion - has no choice but to generate a new key.
	t.Run("generates a new key when the deletion was not observed", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		require.NoError(t, NewProvisioner(client, testNamespace).EnsureSecret(ctx))
		keys := getSecretKeys(t, client)
		require.Len(t, keys, 1)
		assert.NotEqual(t, key1, keys[0])
	})

	// Another antrea-controller, or the user, created the Secret between our Get and our Create. Its
	// key is the one the cluster is converging on, and must not be overwritten.
	t.Run("keeps the key of a Secret created concurrently", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		client.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewAlreadyExists(corev1.Resource("secrets"), apis.AntreaMemberlistSecretName)
		})
		assert.NoError(t, NewProvisioner(client, testNamespace).EnsureSecret(ctx), "an existing Secret is not an error")
	})

	t.Run("reports the errors of the API calls", func(t *testing.T) {
		testCases := []struct {
			name        string
			verb        string
			objects     []runtime.Object
			expectedErr string
		}{
			{
				name:        "get fails",
				verb:        "get",
				expectedErr: "failed to get Secret",
			},
			{
				name:        "create fails",
				verb:        "create",
				expectedErr: "failed to create Secret",
			},
			{
				name:        "update fails",
				verb:        "update",
				objects:     []runtime.Object{newSecret(nil)},
				expectedErr: "failed to add a memberlist key to Secret",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				client := fake.NewSimpleClientset(tc.objects...)
				client.PrependReactor(tc.verb, "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("some API error")
				})
				err := NewProvisioner(client, testNamespace).EnsureSecret(ctx)
				assert.ErrorContains(t, err, tc.expectedErr)
			})
		}
	})
}

// TestProvisionerRetriesOnFailure verifies that a failure to provision the key is retried: the
// antrea-agents cannot secure their gossip traffic, hence cannot assign Egress or ServiceExternalIP
// IPs, until it succeeds.
func TestProvisionerRetriesOnFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := fake.NewSimpleClientset()
		var failCreate atomic.Bool
		failCreate.Store(true)
		client.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if failCreate.Load() {
				return true, nil, fmt.Errorf("some API error")
			}
			return false, nil, nil
		})
		p := NewProvisioner(client, testNamespace)
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			p.Run(ctx)
		}()
		defer func() {
			cancel()
			<-runDone
		}()
		// Sleeping advances the fake clock of the synctest bubble, which lets the informer sync and
		// the rate-limited retries fire, and does not wait for real time.
		settle := func() {
			time.Sleep(2 * minRetryDelay)
			synctest.Wait()
		}

		settle()
		_, err := client.CoreV1().Secrets(testNamespace).Get(ctx, apis.AntreaMemberlistSecretName, metav1.GetOptions{})
		require.True(t, apierrors.IsNotFound(err), "the Secret should not have been created yet")

		failCreate.Store(false)
		settle()
		keys := getSecretKeys(t, client)
		assert.Len(t, keys, 1, "the Secret should have been created by a retry")
	})
}

// TestProvisionerRun verifies that the Provisioner restores the Secret when it is deleted while it
// is running, which is what it watches the Secret for.
func TestProvisionerRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key1}),
		}))
		p := NewProvisioner(client, testNamespace)
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			p.Run(ctx)
		}()
		defer func() {
			cancel()
			<-runDone
		}()
		// settle lets the Provisioner make progress. Sleeping advances the fake clock of the
		// synctest bubble, which the informer needs to sync, and does not wait for real time.
		settle := func() {
			time.Sleep(time.Second)
			synctest.Wait()
		}

		// The Secret already holds a key, which must be left alone.
		settle()
		assert.Equal(t, [][]byte{key1}, getSecretKeys(t, client))

		require.NoError(t, client.CoreV1().Secrets(testNamespace).Delete(ctx, apis.AntreaMemberlistSecretName, metav1.DeleteOptions{}))
		settle()
		assert.Equal(t, [][]byte{key1}, getSecretKeys(t, client), "the Secret should be recreated with the same key")

		// Removing the key from the Secret is handled the same way.
		_, err := client.CoreV1().Secrets(testNamespace).Update(ctx, newSecret(nil), metav1.UpdateOptions{})
		require.NoError(t, err)
		settle()
		assert.Equal(t, [][]byte{key1}, getSecretKeys(t, client), "the key should be restored")
	})
}
