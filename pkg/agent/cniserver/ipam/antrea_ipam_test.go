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

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/containernetworking/cni/pkg/invoke"
	cnitypes "github.com/containernetworking/cni/pkg/types"

	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakecrd "antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

var (
	testApple          = "apple"
	testOrange         = "orange"
	testNoAnnotation   = "empty"
	testJunkAnnotation = "junk"
)

func initTestClients() (*fake.Clientset, *fakecrd.Clientset) {
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

	crdClient := fakecrd.NewSimpleClientset(
		&crdv1a2.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: testApple},
			Spec: crdv1a2.IPPoolSpec{
				IPRanges: []crdv1a2.SubnetIPRange{subnetRangeApple},
			},
		},
		&crdv1a2.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: testOrange},
			Spec: crdv1a2.IPPoolSpec{
				IPRanges: []crdv1a2.SubnetIPRange{subnetRangeOrange},
			},
		},
	)

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

	// Test the driver singleton that was assigned to global variable
	testDriver := antreaIPAMDriver

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	antreaIPAMController, err := InitializeAntreaIPAMController(k8sClient, crdClient, informerFactory)
	require.NoError(t, err, "Expected no error in initialization for Antrea IPAM Controller")
	go antreaIPAMController.Run(stopCh)

	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	networkConfig := []byte("'name': 'testCfg', 'cniVersion': '0.4.0', 'type': 'antrea', 'ipam': {'type': 'antrea-ipam'}}")
	cniArgs := &invoke.Args{
		ContainerID: uuid.New().String(),
	}

	testArgs := make(map[string]*argtypes.K8sArgs)
	for _, testType := range []string{"apple1", "apple2", "orange1", "orange2", testNoAnnotation, testJunkAnnotation} {
		// extract namespace by removing numerals
		re := regexp.MustCompile("[0-9]$")
		namespace := re.ReplaceAllString(testType, "")
		args := argtypes.K8sArgs{}
		cnitypes.LoadArgs(cniservertest.GenerateCNIArgs(testType, namespace, uuid.New().String()), &args)
		testArgs[testType] = &args
	}

	testAdd := func(k8sArgs *argtypes.K8sArgs, expectedIP string, expectedGW string, expectedMask string) {
		owns, data, err := testDriver.Owns(cniArgs, k8sArgs, networkConfig)
		assert.True(t, owns)
		require.NoError(t, err, "expected no error in Owns call")
		require.NotNil(t, data, "expected driver data to be initialized")

		result, err := testDriver.Add(cniArgs, networkConfig, data)
		require.NoError(t, err, "expected no error in Add call")
		assert.Len(t, result.IPs, 1)
		assert.Len(t, result.Routes, 1)
		assert.Equal(t, expectedIP, result.IPs[0].Address.IP.String())
		assert.Equal(t, expectedMask, result.IPs[0].Address.Mask.String())
		assert.Equal(t, expectedGW, result.IPs[0].Gateway.String())
	}

	testAddError := func(k8sArgs *argtypes.K8sArgs) {
		owns, data, err := testDriver.Owns(cniArgs, k8sArgs, networkConfig)
		assert.True(t, owns)
		require.NoError(t, err, "expected no error in Owns call")
		require.NotNil(t, data, "expected driver data to be initialized")

		_, err = testDriver.Add(cniArgs, networkConfig, data)
		require.Error(t, err, "expected error in Add call")
	}

	testDel := func(k8sArgs *argtypes.K8sArgs) {
		owns, data, err := testDriver.Owns(cniArgs, k8sArgs, networkConfig)
		assert.True(t, owns)
		require.NoError(t, err, "expected no error in Owns call")
		require.NotNil(t, data, "expected driver data to be initialized")

		err = testDriver.Del(cniArgs, networkConfig, data)
		require.NoError(t, err, "expected no error in Del call")
	}

	testCheck := func(k8sArgs *argtypes.K8sArgs, shouldExist bool) {
		owns, data, err := testDriver.Owns(cniArgs, k8sArgs, networkConfig)
		assert.True(t, owns)
		require.NoError(t, err, "expected no error in Owns call")
		require.NotNil(t, data, "expected driver data to be initialized")

		err = testDriver.Check(cniArgs, networkConfig, data)
		if shouldExist {
			require.NoError(t, err, "expected no error in Check call")
		} else {
			require.Error(t, err, "expected an error on Check call")
		}
	}

	// Run several adds from two namespaces that have pool annotations
	ipv6Mask := "ffffffffffffffff0000000000000000"
	testAdd(testArgs["apple1"], "10.2.2.100", "10.2.2.1", "ffffff00")
	testAdd(testArgs["orange1"], "20::2", "20::1", ipv6Mask)
	testAdd(testArgs["orange2"], "20::3", "20::1", ipv6Mask)
	testAdd(testArgs["apple2"], "10.2.2.101", "10.2.2.1", "ffffff00")

	// Make sure the driver does not own request without pool annotation
	owns, data, err := testDriver.Owns(cniArgs, testArgs[testNoAnnotation], networkConfig)
	require.NoError(t, err, "expected no error in Owns call")
	assert.False(t, owns)
	require.Nil(t, data, "expected no data returned from Owns call")

	// Verify that annotation for non existent pool errors out
	_, data, err = testDriver.Owns(cniArgs, testArgs[testJunkAnnotation], networkConfig)
	require.NotNil(t, err, "expected error in Owns call due to non-existent pool")
	require.Nil(t, data, "expected no data returned from Owns call")

	// Del two of the pods
	testDel(testArgs["apple1"])
	testDel(testArgs["orange2"])

	// Verify Check call according to the status
	testCheck(testArgs["apple1"], false)
	testCheck(testArgs["apple2"], true)
	testCheck(testArgs["orange1"], true)
	testCheck(testArgs["orange2"], false)

	// Make sure Del call with irrelevant container ID is ignored
	cniArgsBadContainer := &invoke.Args{
		ContainerID: uuid.New().String(),
	}

	owns, data, err = testDriver.Owns(cniArgsBadContainer, testArgs["apple2"], networkConfig)
	assert.True(t, owns)
	require.NoError(t, err, "expected no error in Owns call")
	require.NotNil(t, data, "expected driver data to be initialized")

	err = testDriver.Del(cniArgsBadContainer, networkConfig, data)
	require.NoError(t, err, "expected no error in Del call")

	// Make sure repeated Add works for pod that was previously released
	testAdd(testArgs["apple1"], "10.2.2.100", "10.2.2.1", "ffffff00")

	// Make sure repeated call without previous release results in error
	testAddError(testArgs["apple1"])
}
