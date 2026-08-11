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
	"errors"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/apis"
)

const (
	controllerName = "MemberlistKeyProvisioner"

	minRetryDelay = 5 * time.Second
	maxRetryDelay = time.Minute

	// queueItem is the only item ever added to the queue: it is used purely to serialize the
	// reconciliation of the Secret and to retry it with rate limiting on failure.
	queueItem = "memberlistKeys"

	// keyRestoredMsgSuffix is appended when we had to write back a key which we only had in memory.
	// Such a message is logged as an error, even though we recovered, because it means that the key
	// is only preserved for as long as antrea-controller keeps running.
	keyRestoredMsgSuffix = ". Deleting this Secret, or removing the key it holds, is not supported: had antrea-controller been restarted before the deletion was noticed, a new key would have been generated, and the memberlist cluster would have been partitioned until every antrea-agent applied it"
)

// errInvalidSecretData is returned when the Secret holds data which cannot be parsed. Unlike an API
// error, retrying cannot fix it: only a change to the Secret can, and that is delivered by the
// informer as a new reconciliation. It is therefore not requeued, which would otherwise repeat the
// same error for as long as the Secret is not fixed.
var errInvalidSecretData = errors.New("invalid Secret data")

// Provisioner makes sure that the Secret holding the memberlist keys exists and holds at least one
// valid key, generating a random one if needed. It watches the Secret and reconciles it again if it
// is deleted or if its keys are removed.
type Provisioner struct {
	client    clientset.Interface
	namespace string

	informerFactory informers.SharedInformerFactory
	informer        cache.SharedIndexInformer
	queue           workqueue.TypedRateLimitingInterface[string]

	mutex sync.Mutex
	// knownKeys holds the keys which were last observed in the Secret. They are used to restore the
	// Secret if it is deleted, rather than generating a new key: every antrea-agent would otherwise
	// have to apply the new key, and the memberlist cluster would be partitioned until they all
	// have. It is empty until the Secret has been observed with a valid key, which is the case when
	// antrea-controller is restarted after the Secret was deleted.
	knownKeys [][]byte
}

func NewProvisioner(client clientset.Interface, namespace string) *Provisioner {
	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		0, // no resync: failures are retried by the workqueue, and we only care about actual changes
		informers.WithNamespace(namespace),
		// The field selector is not just an optimization: antrea-controller is only granted access
		// to this specific Secret (by resourceNames), and the API server derives the name of a LIST
		// / WATCH request from an exact match on metadata.name, which is what makes the request
		// authorized.
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("metadata.name=%s", apis.AntreaMemberlistSecretName)
		}),
	)
	p := &Provisioner{
		client:          client,
		namespace:       namespace,
		informerFactory: factory,
		informer:        factory.Core().V1().Secrets().Informer(),
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "memberlistKeyProvisioner",
			},
		),
	}
	// The Secret is reconciled from scratch on every event, so all the events are handled the same
	// way. A deletion matters as much as the rest: the antrea-agents which are already running keep
	// the key they have in memory, but any antrea-agent which restarts afterwards, and every Node
	// added to the cluster, would never get a key and would not claim any Egress or
	// ServiceExternalIP IP.
	p.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { p.queue.Add(queueItem) },
		UpdateFunc: func(_, obj interface{}) { p.queue.Add(queueItem) },
		DeleteFunc: func(obj interface{}) { p.queue.Add(queueItem) },
	})
	return p
}

// Run provisions the memberlist key and keeps the Secret holding it in sync until ctx is done.
// Failing to provision the key is not fatal for antrea-controller: it only prevents the
// antrea-agents from securing their gossip traffic, so we keep retrying in the background and log
// the errors instead of terminating.
func (p *Provisioner) Run(ctx context.Context) {
	defer p.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	p.informerFactory.Start(ctx.Done())
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), p.informer.HasSynced) {
		return
	}
	// No event is delivered when the Secret does not exist, which is the normal case on a new
	// installation, so the first reconciliation is triggered explicitly.
	p.queue.Add(queueItem)

	go wait.UntilWithContext(ctx, p.worker, time.Second)

	<-ctx.Done()
}

func (p *Provisioner) worker(ctx context.Context) {
	for p.processNextItem(ctx) {
	}
}

func (p *Provisioner) processNextItem(ctx context.Context) bool {
	_, quit := p.queue.Get()
	if quit {
		return false
	}
	defer p.queue.Done(queueItem)

	err := p.EnsureSecret(ctx)
	switch {
	case err == nil:
		p.queue.Forget(queueItem)
	case errors.Is(err, errInvalidSecretData):
		// The Secret is left untouched, so that a typo cannot silently rekey a working cluster, and
		// the item is not requeued: only a change to the Secret can resolve this, and the informer
		// delivers it as a new reconciliation.
		p.queue.Forget(queueItem)
		klog.ErrorS(err, "The memberlist key Secret will not be modified, waiting for it to be fixed", "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
	default:
		// EnsureSecret is idempotent and reads the Secret again on every attempt, so it can simply
		// be retried.
		p.queue.AddRateLimited(queueItem)
		klog.ErrorS(err, "Failed to provision the memberlist key, will retry", "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
	}
	return true
}

// EnsureSecret makes sure that the Secret holding the memberlist keys exists and holds at least one
// valid key, generating a random one if needed.
//
// An existing key is never modified: this makes it possible to provision the Secret ahead of the
// Antrea installation, and guarantees that a key chosen by the user - or the key which the cluster
// is already using - is preserved across restarts and upgrades. A key is only written when the
// Secret does not exist yet, or when it does not hold any key at all, and the keys which were last
// observed in the Secret are restored when we still have them, so that deleting the Secret does not
// rekey the cluster. If the Secret holds data which cannot be parsed, an error is returned and the
// Secret is left untouched, so that a typo cannot silently rekey a working cluster.
func (p *Provisioner) EnsureSecret(ctx context.Context) error {
	// The Secret is read with a live request rather than from the informer cache: acting on a stale
	// cache could overwrite a key which was just written, and this only runs when the Secret
	// changes.
	secret, err := p.client.CoreV1().Secrets(p.namespace).Get(ctx, apis.AntreaMemberlistSecretName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get Secret %s: %w", apis.AntreaMemberlistSecretName, err)
		}
		return p.createSecretWithKeys(ctx)
	}
	data := secret.Data[apis.MemberlistSecretKeysKey]
	if len(data) > 0 {
		keys, err := ParseKeys(data)
		if err != nil {
			return fmt.Errorf("%w: Secret %s holds invalid data, please fix it or delete the Secret to have a new key generated: %w", errInvalidSecretData, apis.AntreaMemberlistSecretName, err)
		}
		p.setKnownKeys(keys)
		klog.V(2).InfoS("Secret already holds a memberlist key, keeping it", "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
		return nil
	}
	// The Secret exists but does not hold any key: we are filling a gap rather than overriding a
	// user's choice, e.g. because the Secret was pre-created without any data.
	keys, restored, err := p.keysToInstall()
	if err != nil {
		return err
	}
	secret = secret.DeepCopy()
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[apis.MemberlistSecretKeysKey] = FormatKeys(keys)
	if _, err := p.client.CoreV1().Secrets(p.namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to add a memberlist key to Secret %s: %w", apis.AntreaMemberlistSecretName, err)
	}
	if restored {
		klog.ErrorS(nil, "The memberlist key was removed from the Secret and has been restored"+keyRestoredMsgSuffix, "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
	} else {
		klog.InfoS("Added a randomly-generated memberlist key to the existing Secret", "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
	}
	p.setKnownKeys(keys)
	return nil
}

func (p *Provisioner) createSecretWithKeys(ctx context.Context) error {
	keys, restored, err := p.keysToInstall()
	if err != nil {
		return err
	}
	// We deliberately do not set an owner reference on the Secret: the key must outlive
	// antrea-controller, as deleting and recreating the Deployment would otherwise garbage-collect
	// the Secret and cause a new key to be generated, which would partition the memberlist cluster
	// until every antrea-agent has picked up the new key.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      apis.AntreaMemberlistSecretName,
			Namespace: p.namespace,
			Labels:    map[string]string{"app": "antrea"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			apis.MemberlistSecretKeysKey: FormatKeys(keys),
		},
	}
	if _, err := p.client.CoreV1().Secrets(p.namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// The Secret was created concurrently - by the user, or by another antrea-controller
			// during a rolling update - and we must not overwrite the key it holds. knownKeys is
			// deliberately left alone rather than set to the keys we were about to write: those are
			// not the keys the cluster ends up using. The informer delivers the creation as a new
			// reconciliation, and EnsureSecret then records the keys the Secret actually holds.
			klog.InfoS("Secret was created concurrently, keeping the key it holds", "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
			return nil
		}
		return fmt.Errorf("failed to create Secret %s: %w", apis.AntreaMemberlistSecretName, err)
	}
	if restored {
		klog.ErrorS(nil, "The Secret holding the memberlist key was deleted and has been recreated with the same key"+keyRestoredMsgSuffix, "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
	} else {
		klog.InfoS("Created Secret with a randomly-generated memberlist key", "secret", klog.KRef(p.namespace, apis.AntreaMemberlistSecretName))
	}
	p.setKnownKeys(keys)
	return nil
}

// keysToInstall returns the keys to write to the Secret: the keys which were last observed in it if
// we still have them - restoring them keeps the memberlist cluster on the key it is already using -
// and a new random key otherwise. The second return value reports whether existing keys are being
// restored.
func (p *Provisioner) keysToInstall() ([][]byte, bool, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.knownKeys) > 0 {
		return p.knownKeys, true, nil
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, false, err
	}
	return [][]byte{key}, false, nil
}

func (p *Provisioner) setKnownKeys(keys [][]byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.knownKeys = keys
}
