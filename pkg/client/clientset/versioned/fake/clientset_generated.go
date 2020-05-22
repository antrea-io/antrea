// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	clusterinformationv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/clusterinformation/v1beta1"
	fakeclusterinformationv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/clusterinformation/v1beta1/fake"
	corev1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/core/v1beta1"
	fakecorev1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/core/v1beta1/fake"
	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/networking/v1beta1"
	fakenetworkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/networking/v1beta1/fake"
<<<<<<< HEAD
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/system/v1beta1"
	fakesystemv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/system/v1beta1/fake"
=======
	securityv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/security/v1beta1"
	fakesecurityv1beta1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/security/v1beta1/fake"
>>>>>>> Add API types for Namespaced Antrea NetworkPolicy
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/testing"
)

// NewSimpleClientset returns a clientset that will respond with the provided objects.
// It's backed by a very simple object tracker that processes creates, updates and deletions as-is,
// without applying any validations and/or defaults. It shouldn't be considered a replacement
// for a real clientset and is mostly useful in simple unit tests.
func NewSimpleClientset(objects ...runtime.Object) *Clientset {
	o := testing.NewObjectTracker(scheme, codecs.UniversalDecoder())
	for _, obj := range objects {
		if err := o.Add(obj); err != nil {
			panic(err)
		}
	}

	cs := &Clientset{tracker: o}
	cs.discovery = &fakediscovery.FakeDiscovery{Fake: &cs.Fake}
	cs.AddReactor("*", "*", testing.ObjectReaction(o))
	cs.AddWatchReactor("*", func(action testing.Action) (handled bool, ret watch.Interface, err error) {
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := o.Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		return true, watch, nil
	})

	return cs
}

// Clientset implements clientset.Interface. Meant to be embedded into a
// struct to get a default implementation. This makes faking out just the method
// you want to test easier.
type Clientset struct {
	testing.Fake
	discovery *fakediscovery.FakeDiscovery
	tracker   testing.ObjectTracker
}

func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	return c.discovery
}

func (c *Clientset) Tracker() testing.ObjectTracker {
	return c.tracker
}

var _ clientset.Interface = &Clientset{}

// ClusterinformationV1beta1 retrieves the ClusterinformationV1beta1Client
func (c *Clientset) ClusterinformationV1beta1() clusterinformationv1beta1.ClusterinformationV1beta1Interface {
	return &fakeclusterinformationv1beta1.FakeClusterinformationV1beta1{Fake: &c.Fake}
}

// CoreV1beta1 retrieves the CoreV1beta1Client
func (c *Clientset) CoreV1beta1() corev1beta1.CoreV1beta1Interface {
	return &fakecorev1beta1.FakeCoreV1beta1{Fake: &c.Fake}
}

// NetworkingV1beta1 retrieves the NetworkingV1beta1Client
func (c *Clientset) NetworkingV1beta1() networkingv1beta1.NetworkingV1beta1Interface {
	return &fakenetworkingv1beta1.FakeNetworkingV1beta1{Fake: &c.Fake}
}

<<<<<<< HEAD
// SystemV1beta1 retrieves the SystemV1beta1Client
func (c *Clientset) SystemV1beta1() systemv1beta1.SystemV1beta1Interface {
	return &fakesystemv1beta1.FakeSystemV1beta1{Fake: &c.Fake}
=======
// SecurityV1beta1 retrieves the SecurityV1beta1Client
func (c *Clientset) SecurityV1beta1() securityv1beta1.SecurityV1beta1Interface {
	return &fakesecurityv1beta1.FakeSecurityV1beta1{Fake: &c.Fake}
>>>>>>> Add API types for Namespaced Antrea NetworkPolicy
}
