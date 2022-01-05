// Copyright 2021 Antrea Authors
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

package ipam

import (
	"regexp"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8suuid "k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	fakepoolclient "antrea.io/antrea/pkg/ipam/poolallocator/testing"
)

var (
	testApple          = "apple"
	testOrange         = "orange"
	testNoAnnotation   = "empty"
	testJunkAnnotation = "junk"
)

func createIPPools(crdClient *fakepoolclient.IPPoolClientset) {

	ipRangeApple := crdv1a2.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.200",
	}

	subnetInfoApple := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}

	subnetRangeApple := crdv1a2.SubnetIPRange{IPRange: ipRangeApple,
		SubnetInfo: subnetInfoApple}

	crdClient.InitPool(&crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: testApple,
			UID: k8suuid.NewUUID()},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRangeApple},
		},
	})

	ipRangeOrange := crdv1a2.IPRange{
		Start: "20::2",
		End:   "20::20",
	}

	subnetInfoOrange := crdv1a2.SubnetInfo{
		Gateway:      "20::1",
		PrefixLength: 64,
	}

	subnetRangeOrange := crdv1a2.SubnetIPRange{IPRange: ipRangeOrange,
		SubnetInfo: subnetInfoOrange}

	crdClient.InitPool(&crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: testOrange,
			UID: k8suuid.NewUUID()},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRangeOrange},
		},
	})
}

func initTestClients() (*fake.Clientset, *fakepoolclient.IPPoolClientset) {
	crdClient := fakepoolclient.NewIPPoolClient()

	k8sClient := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testApple,
				Annotations: map[string]string{AntreaIPAMAnnotationKey: testApple, "junk": "garbage"},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testOrange,
				Annotations: map[string]string{"junk": "garbage", AntreaIPAMAnnotationKey: testOrange},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testJunkAnnotation,
				Annotations: map[string]string{AntreaIPAMAnnotationKey: testJunkAnnotation},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNoAnnotation,
			},
		})

	return k8sClient, crdClient
}

func TestAntreaIPAMDriver(t *testing.T) {
	stopCh := make(chan struct{})

	k8sClient, crdClient := initTestClients()

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)

	antreaIPAMController, err := InitializeAntreaIPAMController(k8sClient, crdClient, informerFactory, crdInformerFactory)
	require.NoError(t, err, "Expected no error in initialization for Antrea IPAM Controller")
	informerFactory.Start(stopCh)

	createIPPools(crdClient)

	informerFactory.WaitForCacheSync(stopCh)

	go antreaIPAMController.Run(stopCh)
	crdInformerFactory.Start(stopCh)
	crdInformerFactory.WaitForCacheSync(stopCh)

	// Test the driver singleton that was assigned to global variable
	testDriver := antreaIPAMDriver

	networkConfig := []byte("'name': 'testCfg', 'cniVersion': '0.4.0', 'type': 'antrea', 'ipam': {'type': 'antrea-ipam'}}")

	cniArgsMap := make(map[string]*invoke.Args)
	k8sArgsMap := make(map[string]*argtypes.K8sArgs)
	for _, test := range []string{"apple1", "apple2", "orange1", "orange2", testNoAnnotation, testJunkAnnotation} {
		// extract Namespace by removing numerals
		re := regexp.MustCompile("[0-9]$")
		namespace := re.ReplaceAllString(test, "")
		args := argtypes.K8sArgs{}
		cnitypes.LoadArgs(cniservertest.GenerateCNIArgs(test, namespace, uuid.New().String()), &args)
		k8sArgsMap[test] = &args
		cniArgsMap[test] = &invoke.Args{
			ContainerID: uuid.New().String(),
		}
	}

	testAdd := func(test string, expectedIP string, expectedGW string, expectedMask string) {
		owns, result, err := testDriver.Add(cniArgsMap[test], k8sArgsMap[test], networkConfig)
		require.NoError(t, err, "expected no error in Add call")
		assert.True(t, owns)
		assert.Len(t, result.IPs, 1)
		assert.Len(t, result.Routes, 1)
		assert.Equal(t, expectedIP, result.IPs[0].Address.IP.String())
		assert.Equal(t, expectedMask, result.IPs[0].Address.Mask.String())
		assert.Equal(t, expectedGW, result.IPs[0].Gateway.String())
	}

	testAddError := func(test string) {
		owns, _, err := testDriver.Add(cniArgsMap[test], k8sArgsMap[test], networkConfig)
		assert.True(t, owns)
		require.Error(t, err, "expected error in Add call")
	}

	testDel := func(test string) {
		owns, err := testDriver.Del(cniArgsMap[test], k8sArgsMap[test], networkConfig)
		assert.True(t, owns)
		require.NoError(t, err, "expected no error in Del call")
	}

	testCheck := func(test string, shouldExist bool) {
		owns, err := testDriver.Check(cniArgsMap[test], k8sArgsMap[test], networkConfig)
		assert.True(t, owns)
		if shouldExist {
			require.NoError(t, err, "expected no error in Check call")
		} else {
			require.Error(t, err, "expected an error on Check call")
		}
	}

	// Run several adds from two Namespaces that have pool annotations
	ipv6Mask := "ffffffffffffffff0000000000000000"
	testAdd("apple1", "10.2.2.100", "10.2.2.1", "ffffff00")

	// introduce new IP Pool in mid-action
	testAdd("orange1", "20::2", "20::1", ipv6Mask)
	testAdd("orange2", "20::3", "20::1", ipv6Mask)
	testAdd("apple2", "10.2.2.101", "10.2.2.1", "ffffff00")

	// Make sure the driver does not own request without pool annotation
	owns, _, err := testDriver.Add(cniArgsMap[testNoAnnotation], k8sArgsMap[testNoAnnotation], networkConfig)
	require.NoError(t, err, "expected no error in Add call without pool annotation")
	assert.False(t, owns)

	// Verify that annotation for non existent pool errors out
	owns, _, err = testDriver.Add(cniArgsMap[testJunkAnnotation], k8sArgsMap[testJunkAnnotation], networkConfig)
	require.NotNil(t, err, "expected error in Add call due to non-existent pool")
	assert.True(t, owns)

	// Del two of the Pods
	testDel("apple1")
	testDel("orange2")

	// Verify last update was propagated to informer
	err = wait.PollImmediate(100*time.Millisecond, 1*time.Second, func() (bool, error) {
		owns, err := testDriver.Check(cniArgsMap["orange2"], k8sArgsMap["orange2"], networkConfig)
		if err != nil {
			// container already relelased
			return true, nil
		}
		return !owns, nil
	})

	require.NoError(t, err, "orange2 pod was not released")

	// Verify Check call according to the status
	testCheck("apple1", false)
	testCheck("apple2", true)
	testCheck("orange1", true)

	// Make sure Del call with irrelevant container ID is ignored
	cniArgsBadContainer := &invoke.Args{
		ContainerID: uuid.New().String(),
	}

	owns, err = testDriver.Del(cniArgsBadContainer, k8sArgsMap["orange1"], networkConfig)
	assert.True(t, owns)
	require.NoError(t, err, "expected no error in Del call")

	// Make sure repeated Add works for Pod that was previously released
	testAdd("apple1", "10.2.2.100", "10.2.2.1", "ffffff00")

	// Make sure repeated call for previous container results in error
	testAddError("apple2")
}
