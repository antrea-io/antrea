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
	"context"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/v2/pkg/apis"
)

// keyCollector records the keys delivered to the SecretWatcher handler. Tests run inside a synctest
// bubble, so a delivery which is due has always happened by the time synctest.Wait returns.
type keyCollector struct {
	mutex sync.Mutex
	keys  [][][]byte
}

func (c *keyCollector) onKeys(keys [][]byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.keys = append(c.keys, keys)
}

// take returns the deliveries made since the last call.
func (c *keyCollector) take(t *testing.T) [][][]byte {
	t.Helper()
	synctest.Wait()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	keys := c.keys
	c.keys = nil
	return keys
}

// assertKeys asserts that a single delivery was made, with the expected keys.
func (c *keyCollector) assertKeys(t *testing.T, expected [][]byte) {
	t.Helper()
	assert.Equal(t, [][][]byte{expected}, c.take(t))
}

func (c *keyCollector) assertNoKeys(t *testing.T) {
	t.Helper()
	assert.Empty(t, c.take(t), "no keys should have been delivered")
}

func TestSecretWatcher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		stopCh := make(chan struct{})
		defer close(stopCh)

		client := fake.NewSimpleClientset()
		w := NewSecretWatcher(client, testNamespace)
		collector := &keyCollector{}
		w.Watch(stopCh, collector.onKeys)

		// No Secret yet: nothing must be delivered.
		collector.assertNoKeys(t)

		// A Secret with invalid data is ignored.
		secret := newSecret(map[string][]byte{apis.MemberlistSecretKeysKey: []byte("not-a-key")})
		_, err := client.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
		require.NoError(t, err)
		collector.assertNoKeys(t)

		// The initial valid keys are delivered.
		secret.Data[apis.MemberlistSecretKeysKey] = FormatKeys([][]byte{key1})
		_, err = client.CoreV1().Secrets(testNamespace).Update(ctx, secret, metav1.UpdateOptions{})
		require.NoError(t, err)
		collector.assertKeys(t, [][]byte{key1})

		// An update which does not change the keys is not delivered again.
		secret.Annotations = map[string]string{"foo": "bar"}
		_, err = client.CoreV1().Secrets(testNamespace).Update(ctx, secret, metav1.UpdateOptions{})
		require.NoError(t, err)
		collector.assertNoKeys(t)

		// A key change is delivered.
		secret.Data[apis.MemberlistSecretKeysKey] = FormatKeys([][]byte{key2, key1})
		_, err = client.CoreV1().Secrets(testNamespace).Update(ctx, secret, metav1.UpdateOptions{})
		require.NoError(t, err)
		collector.assertKeys(t, [][]byte{key2, key1})

		// Deleting the Secret is ignored: the keys in use must stay valid.
		require.NoError(t, client.CoreV1().Secrets(testNamespace).Delete(ctx, apis.AntreaMemberlistSecretName, metav1.DeleteOptions{}))
		collector.assertNoKeys(t)
	})
}

func TestSecretWatcherInitialKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stopCh := make(chan struct{})
		defer close(stopCh)

		// The Secret already exists when the watcher starts: the keys must be delivered without any
		// further change to the Secret.
		client := fake.NewSimpleClientset(newSecret(map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys([][]byte{key1}),
		}))
		w := NewSecretWatcher(client, testNamespace)
		collector := &keyCollector{}
		w.Watch(stopCh, collector.onKeys)
		collector.assertKeys(t, [][]byte{key1})
	})
}
