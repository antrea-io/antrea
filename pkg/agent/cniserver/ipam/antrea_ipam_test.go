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
	"context"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8suuid "k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	annotations "antrea.io/antrea/pkg/ipam"
	fakepoolclient "antrea.io/antrea/pkg/ipam/poolallocator/testing"
)

var (
	testApple          = "apple"
	testOrange         = "orange"
	testPear           = "pear"
	testNoAnnotation   = "empty"
	testJunkAnnotation = "junk"

	testCNIVersion = current.ImplementedSpecVersion
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

	ipRangePear := crdv1a2.IPRange{
		Start: "10.2.3.100",
		End:   "10.2.3.200",
	}
	subnetInfoPear := crdv1a2.SubnetInfo{
		Gateway:      "10.2.3.1",
		PrefixLength: 24,
		VLAN:         100,
	}
	subnetRangePear := crdv1a2.SubnetIPRange{IPRange: ipRangePear,
		SubnetInfo: subnetInfoPear}
	crdClient.InitPool(&crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: testPear},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges:  []crdv1a2.SubnetIPRange{subnetRangePear},
			IPVersion: crdv1a2.IPv4,
		},
		Status: crdv1a2.IPPoolStatus{IPAddresses: []crdv1a2.IPAddressState{{
			IPAddress: "10.2.3.198",
			Phase:     crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &crdv1a2.StatefulSetOwner{
				Name:      "pear-sts",
				Namespace: testPear,
				Index:     8,
			}},
		}, {
			IPAddress: "10.2.3.197",
			Phase:     crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{
				Pod: &crdv1a2.PodOwner{
					Name:        "pear-sts-9",
					Namespace:   testPear,
					ContainerID: "pear-sts-9-container",
				},
				StatefulSet: &crdv1a2.StatefulSetOwner{
					Name:      "pear-sts",
					Namespace: testPear,
					Index:     9,
				}},
		}, {
			IPAddress: "10.2.3.196",
			Phase:     crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{
				Pod: &crdv1a2.PodOwner{
					Name:        "pear10",
					Namespace:   testPear,
					ContainerID: "pear10-container",
				}},
		}}},
	})
}

func initTestClients() (*fake.Clientset, *fakepoolclient.IPPoolClientset) {
	crdClient := fakepoolclient.NewIPPoolClient()

	bTrue := true
	k8sClient := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testApple,
				Annotations: map[string]string{annotations.AntreaIPAMAnnotationKey: testApple, "junk": "garbage"},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testOrange,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testOrange},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testPear,
				Annotations: map[string]string{"junk": "garbage"},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testJunkAnnotation,
				Annotations: map[string]string{annotations.AntreaIPAMAnnotationKey: testJunkAnnotation},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNoAnnotation,
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "apple1",
				Namespace: testApple,
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "apple2",
				Namespace: testApple,
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "apple-sts-0",
				Namespace:       testApple,
				OwnerReferences: []metav1.OwnerReference{{Controller: &bTrue, Kind: "StatefulSet"}},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "orange1",
				Namespace: testOrange,
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "orange2",
				Namespace: testOrange,
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "pear1",
				Namespace:   testPear,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testPear},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "pear2",
				Namespace:   testPear,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testPear, annotations.AntreaIPAMPodIPAnnotationKey: " "},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "pear3",
				Namespace:   testPear,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testPear, annotations.AntreaIPAMPodIPAnnotationKey: "10.2.3.199"},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				// conflict
				Name:        "pear4",
				Namespace:   testPear,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testPear, annotations.AntreaIPAMPodIPAnnotationKey: "10.2.3.199"},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				// out of range
				Name:        "pear5",
				Namespace:   testPear,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testPear, annotations.AntreaIPAMPodIPAnnotationKey: "10.2.4.199"},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				// invalid IP
				Name:        "pear6",
				Namespace:   testPear,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testPear, annotations.AntreaIPAMPodIPAnnotationKey: "junk"},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				// invalid IPPool
				Name:        "pear7",
				Namespace:   testPear,
				Annotations: map[string]string{"junk": "garbage", annotations.AntreaIPAMAnnotationKey: testJunkAnnotation},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pear-sts-8",
				Namespace:       testPear,
				Annotations:     map[string]string{annotations.AntreaIPAMAnnotationKey: testPear},
				OwnerReferences: []metav1.OwnerReference{{Controller: &bTrue, Kind: "StatefulSet"}},
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testNoAnnotation,
				Namespace: testNoAnnotation,
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testJunkAnnotation,
				Namespace: testJunkAnnotation,
			},
			Spec: corev1.PodSpec{NodeName: "fakeNode"},
		})

	return k8sClient, crdClient
}

func TestAntreaIPAMDriver(t *testing.T) {
	stopCh := make(chan struct{})

	k8sClient, crdClient := initTestClients()

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	listOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", "fakeNode").String()
	}
	localPodInformer := coreinformers.NewFilteredPodInformer(
		k8sClient,
		metav1.NamespaceAll,
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, // NamespaceIndex is used in NPLController.
		listOptions,
	)

	antreaIPAMController, err := InitializeAntreaIPAMController(crdClient, informerFactory.Core().V1().Namespaces(), crdInformerFactory.Crd().V1alpha2().IPPools(), localPodInformer, true)
	require.NoError(t, err, "Expected no error in initialization for Antrea IPAM Controller")
	informerFactory.Start(stopCh)
	go localPodInformer.Run(stopCh)

	createIPPools(crdClient)

	informerFactory.WaitForCacheSync(stopCh)

	go antreaIPAMController.Run(stopCh)
	crdInformerFactory.Start(stopCh)
	crdInformerFactory.WaitForCacheSync(stopCh)

	// Test the driver singleton that was assigned to global variable
	testDriver := antreaIPAMDriver

	networkConfig := []byte("'name': 'testCfg', 'cniVersion': '0.4.0', 'type': 'antrea', 'ipam': {'type': 'antrea'}}")

	cniArgsMap := make(map[string]*invoke.Args)
	k8sArgsMap := make(map[string]*argtypes.K8sArgs)
	vlanArgsMap := map[string]uint16{"pear1": 100, "pear2": 100, "pear3": 100, "pear-sts-8": 100}
	for _, test := range []string{"apple1", "apple2", "apple-sts-0", "orange1", "orange2", testNoAnnotation, testJunkAnnotation, "pear1", "pear2", "pear3", "pear4", "pear5", "pear6", "pear7", "pear-sts-8", "pear-sts-9", "pear10"} {
		// extract Namespace by removing numerals
		re := regexp.MustCompile("(-sts-)*[0-9]*$")
		namespace := re.ReplaceAllString(test, "")
		args := argtypes.K8sArgs{}
		cnitypes.LoadArgs(cniservertest.GenerateCNIArgs(test, namespace, uuid.New().String()), &args)
		k8sArgsMap[test] = &args
		cniArgsMap[test] = &invoke.Args{
			ContainerID: fmt.Sprintf("%s-container", test),
		}
	}

	testAdd := func(test string, expectedIP string, expectedGW string, expectedMask string, isReserved bool) {
		owns, result, err := testDriver.Add(cniArgsMap[test], k8sArgsMap[test], networkConfig)
		require.NoError(t, err, "expected no error in Add call")
		assert.True(t, owns)
		assert.Len(t, result.IPs, 1)
		assert.Len(t, result.Routes, 1)
		assert.Equal(t, expectedIP, result.IPs[0].Address.IP.String())
		assert.Equal(t, expectedMask, result.IPs[0].Address.Mask.String())
		assert.Equal(t, expectedGW, result.IPs[0].Gateway.String())
		if vlanID, ok := vlanArgsMap[test]; ok {
			assert.Equal(t, vlanID, result.VLANID)
		} else {
			assert.Equal(t, uint16(0), result.VLANID)
		}

		podNamespace := string(k8sArgsMap[test].K8S_POD_NAMESPACE)
		podName := string(k8sArgsMap[test].K8S_POD_NAME)
		err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond*200, time.Second, false, func(ctx context.Context) (bool, error) {
			ipPool, _ := antreaIPAMController.ipPoolLister.Get(podNamespace)
			found := false
			for _, ipAddress := range ipPool.Status.IPAddresses {
				if expectedIP == ipAddress.IPAddress {
					assert.Equal(t, ipAddress.Owner.StatefulSet != nil, isReserved)
					if ipAddress.Owner.StatefulSet != nil {
						assert.Equal(t, podName, fmt.Sprintf("%s-%d", ipAddress.Owner.StatefulSet.Name, ipAddress.Owner.StatefulSet.Index))
						assert.Equal(t, podNamespace, ipAddress.Owner.StatefulSet.Namespace)
					}
					assert.Equal(t, podName, ipAddress.Owner.Pod.Name)
					assert.Equal(t, podNamespace, ipAddress.Owner.Pod.Namespace)
					found = true
					break
				}
			}
			return found == true, nil
		})
		assert.Nil(t, err)
	}

	testAddError := func(test string) {
		owns, _, err := testDriver.Add(cniArgsMap[test], k8sArgsMap[test], networkConfig)
		assert.True(t, owns)
		require.Error(t, err, "expected error in Add call")
	}

	testDel := func(test string, isReserved bool) {
		owns, err := testDriver.Del(cniArgsMap[test], k8sArgsMap[test], networkConfig)
		assert.True(t, owns)
		require.NoError(t, err, "expected no error in Del call")

		podNamespace := string(k8sArgsMap[test].K8S_POD_NAMESPACE)
		podName := string(k8sArgsMap[test].K8S_POD_NAME)
		err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond*200, time.Second, false, func(ctx context.Context) (bool, error) {
			ipPool, _ := antreaIPAMController.ipPoolLister.Get(podNamespace)
			found := false
			for _, ipAddress := range ipPool.Status.IPAddresses {
				if ipAddress.Owner.Pod != nil && ipAddress.Owner.Pod.Name == podName && ipAddress.Owner.Pod.Namespace == podNamespace {
					t.Logf("IP allocation is not removed")
					return false, nil
				}
				if ipAddress.Owner.StatefulSet != nil && podName == fmt.Sprintf("%s-%d", ipAddress.Owner.StatefulSet.Name, ipAddress.Owner.StatefulSet.Index) && podNamespace == ipAddress.Owner.StatefulSet.Namespace {
					found = true
					break
				}
			}
			return found == isReserved, nil
		})
		assert.Nil(t, err)
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
	testAdd("apple1", "10.2.2.100", "10.2.2.1", "ffffff00", false)

	// introduce new IP Pool in mid-action
	testAdd("orange1", "20::2", "20::1", ipv6Mask, false)
	testAdd("orange2", "20::3", "20::1", ipv6Mask, false)
	testAdd("apple2", "10.2.2.101", "10.2.2.1", "ffffff00", false)
	testAdd("apple-sts-0", "10.2.2.102", "10.2.2.1", "ffffff00", true)
	testAdd("pear1", "10.2.3.100", "10.2.3.1", "ffffff00", false)
	testAdd("pear2", "10.2.3.101", "10.2.3.1", "ffffff00", false)
	testAdd("pear3", "10.2.3.199", "10.2.3.1", "ffffff00", false)
	testAdd("pear-sts-8", "10.2.3.198", "10.2.3.1", "ffffff00", true)

	// Make sure the driver does not own request without pool annotation
	owns, _, err := testDriver.Add(cniArgsMap[testNoAnnotation], k8sArgsMap[testNoAnnotation], networkConfig)
	require.NoError(t, err, "expected no error in Add call without pool annotation")
	assert.False(t, owns)

	// Verify that annotation for non existent pool errors out
	owns, _, err = testDriver.Add(cniArgsMap[testJunkAnnotation], k8sArgsMap[testJunkAnnotation], networkConfig)
	require.NotNil(t, err, "expected error in Add call due to non-existent pool")
	assert.True(t, owns)

	// Verify that annotation for conflict ip errors
	owns, _, err = testDriver.Add(cniArgsMap["pear4"], k8sArgsMap["pear4"], networkConfig)
	require.NotNil(t, err, "expected error in Add call due to conflict ip")
	assert.True(t, owns)

	// Verify that annotation for ip out of range errors
	owns, _, err = testDriver.Add(cniArgsMap["pear5"], k8sArgsMap["pear5"], networkConfig)
	require.NotNil(t, err, "expected error in Add call due to ip out of range")
	assert.True(t, owns)

	// Verify that annotation for invalid ip errors
	owns, _, err = testDriver.Add(cniArgsMap["pear6"], k8sArgsMap["pear6"], networkConfig)
	require.NotNil(t, err, "expected error in Add call due to invalid ip")
	assert.True(t, owns)

	// Verify that annotation for non existent pool errors out
	owns, _, err = testDriver.Add(cniArgsMap["pear7"], k8sArgsMap["pear7"], networkConfig)
	require.NotNil(t, err, "expected error in Add call due to non-existent pool")
	assert.True(t, owns)

	// Del two of the Pods
	testDel("apple1", false)
	testDel("orange2", false)
	testDel("pear3", false)
	testDel("apple-sts-0", true)
	testDel("pear-sts-8", true)
	testDel("pear-sts-9", true)
	testDel("pear10", false)

	// Verify last update was propagated to informer
	err = wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 1*time.Second, true,
		func(ctx context.Context) (bool, error) {
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
	testCheck("orange2", false)
	testCheck("pear1", true)
	testCheck("pear2", true)
	testCheck("pear3", false)
	testCheck("apple-sts-0", false)
	testCheck("pear-sts-8", false)

	// Make sure Del call with irrelevant container ID is ignored
	cniArgsBadContainer := &invoke.Args{
		ContainerID: uuid.New().String(),
	}

	owns, err = testDriver.Del(cniArgsBadContainer, k8sArgsMap["orange1"], networkConfig)
	assert.False(t, owns)
	require.NoError(t, err, "expected no error in Del call")

	// Make sure repeated Add works for Pod that was previously released
	testAdd("apple1", "10.2.2.100", "10.2.2.1", "ffffff00", false)
	testAdd("apple-sts-0", "10.2.2.102", "10.2.2.1", "ffffff00", true)

	// Make sure repeated call for previous container gets identical result
	testAdd("apple2", "10.2.2.101", "10.2.2.1", "ffffff00", false)

	// Make sure repeated Add works for pod that was previously released
	testAdd("pear3", "10.2.3.199", "10.2.3.1", "ffffff00", false)

	// Make sure repeated call without previous container results in error
	testAddError("pear3")
}

func TestSecondaryNetworkAdd(t *testing.T) {
	testCases := []struct {
		name        string
		networkConf *argtypes.NetworkConfig
		initFunc    func(stopCh chan struct{}) *AntreaIPAM
		expectedRes error
	}{
		{
			name: "Both Antrea IPPool and static address are empty",
			networkConf: &argtypes.NetworkConfig{
				CNIVersion: testCNIVersion,
				IPAM: &argtypes.IPAMConfig{
					IPPools: []string{},
				},
			},
			expectedRes: fmt.Errorf("at least one Antrea IPPool or static address must be specified"),
		},
		{
			name: "Specify the static IP Address",
			networkConf: &argtypes.NetworkConfig{
				CNIVersion: testCNIVersion,
				IPAM: &argtypes.IPAMConfig{
					Addresses: []argtypes.Address{
						{Address: "192.168.1.1/24"},
					},
				},
			},
		},
		{
			name: "Antrea IPAM driver not ready",
			networkConf: &argtypes.NetworkConfig{
				CNIVersion: testCNIVersion,
				IPAM: &argtypes.IPAMConfig{
					IPPools: []string{
						testApple,
					},
				},
			},
			expectedRes: fmt.Errorf("Antrea IPAM driver not ready: context deadline exceeded"),
		},
		{
			name: "Add secondary network successfully",
			networkConf: &argtypes.NetworkConfig{
				CNIVersion: testCNIVersion,
				IPAM: &argtypes.IPAMConfig{
					IPPools: []string{
						testApple,
					},
				},
			},
			expectedRes: nil,
			initFunc: func(stopCh chan struct{}) *AntreaIPAM {
				k8sClient, crdClient := initTestClients()

				informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
				crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
				listOptions := func(options *metav1.ListOptions) {
					options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", "fakeNode").String()
				}
				localPodInformer := coreinformers.NewFilteredPodInformer(
					k8sClient,
					metav1.NamespaceAll,
					0,
					cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, // NamespaceIndex is used in NPLController.
					listOptions,
				)

				antreaIPAMController, err := InitializeAntreaIPAMController(crdClient,
					informerFactory.Core().V1().Namespaces(),
					crdInformerFactory.Crd().V1alpha2().IPPools(),
					localPodInformer,
					true,
				)
				require.NoError(t, err, "Expected no error in initialization for Antrea IPAM Controller")
				createIPPools(crdClient)

				go antreaIPAMController.Run(stopCh)
				crdInformerFactory.Start(stopCh)
				crdInformerFactory.WaitForCacheSync(stopCh)

				return &AntreaIPAM{
					controller:      antreaIPAMController,
					controllerMutex: sync.RWMutex{},
				}
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			var d *AntreaIPAM
			if tt.initFunc == nil {
				d = &AntreaIPAM{}
			} else {
				stopCh := make(chan struct{})
				d = tt.initFunc(stopCh)
				defer close(stopCh)
			}

			args := &invoke.Args{
				ContainerID: "container-id",
			}
			k8sArgs := &argtypes.K8sArgs{
				CommonArgs:        cnitypes.CommonArgs{},
				K8S_POD_NAME:      "test-pod",
				K8S_POD_NAMESPACE: "test-ns",
			}

			_, err := d.secondaryNetworkAdd(args, k8sArgs, tt.networkConf)
			assert.Equal(t, tt.expectedRes, err)
		})
	}
}
