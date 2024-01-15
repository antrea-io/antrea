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

package framework

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/ipam/ipallocator"
	"antrea.io/antrea/test/e2e/providers"
	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework/client_pod"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleService", ScaleService)
}

func ScaleService(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error

	var svcs []ServiceInfo
	svcs, err = scaleUp(ctx, data, ch)
	if err != nil {
		res.err = fmt.Errorf("scale up services error: %v", err)
		return
	}
	res.scaleNum = len(svcs)

	defer func() {
		res.err = err
		for {
			klog.InfoS("Waiting the check goroutine finish", "len(svcs)", len(svcs))
			if len(ch) == len(svcs) {
				break
			}
			klog.InfoS("Waiting the check goroutine finish")
			time.Sleep(time.Second)
		}
		if err = scaleDown(ctx, data, svcs); err != nil {
			klog.ErrorS(err, "Scale down Services failed")
		}
	}()

	return
}

type ServiceInfo struct {
	Name      string
	IP        string
	NameSpace string
}

func retrieveCIDRs(provider providers.ProviderInterface, controlPlaneNodeName string, cmd string, reg string) ([]string, error) {
	res := make([]string, 2)
	rc, stdout, _, err := provider.RunCommandOnNode(controlPlaneNodeName, cmd)
	if err != nil || rc != 0 {
		return res, fmt.Errorf("error when running the following command `%s` on control-plane Node: %v, %s", cmd, err, stdout)
	}
	re := regexp.MustCompile(reg)
	matches := re.FindStringSubmatch(stdout)
	if len(matches) == 0 {
		return res, fmt.Errorf("cannot retrieve CIDR, unexpected kubectl output: %s", stdout)
	}
	cidrs := strings.Split(matches[1], ",")
	if len(cidrs) == 1 {
		_, cidr, err := net.ParseCIDR(cidrs[0])
		if err != nil {
			return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
		}
		if cidr.IP.To4() != nil {
			res[0] = cidrs[0]
		} else {
			res[1] = cidrs[0]
		}
	} else if len(cidrs) == 2 {
		_, cidr, err := net.ParseCIDR(cidrs[0])
		if err != nil {
			return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
		}
		if cidr.IP.To4() != nil {
			res[0] = cidrs[0]
			res[1] = cidrs[1]
		} else {
			res[0] = cidrs[1]
			res[1] = cidrs[0]
		}
	} else {
		return res, fmt.Errorf("unexpected cluster CIDR: %s", matches[1])
	}
	return res, nil
}

func unmarshallService(yamlFile string) (*corev1.Service, error) {
	klog.InfoS("ReadYamlFile", "yamlFile", yamlFile)
	podBytes, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %+v", err)
	}
	service := &corev1.Service{}

	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(podBytes), 100)

	if err := decoder.Decode(service); err != nil {
		return nil, fmt.Errorf("error decoding YAML file: %+v", err)
	}
	return service, nil
}

func renderServices(templatePath string, num int) (svcs []*corev1.Service, err error) {
	yamlFile := path.Join(templatePath, "service/service.yaml")
	var service *corev1.Service
	service, err = unmarshallService(yamlFile)
	if err != nil {
		err = fmt.Errorf("error reading Service template: %+v", err)
		return nil, err
	}

	for i := 0; i < num; i++ {
		svc := &corev1.Service{Spec: service.Spec}
		svc.Name = fmt.Sprintf("antrea-scale-svc-%d-%s", i, uuid.New().String())
		svc.Spec.Selector = map[string]string{
			fmt.Sprintf("%s%d", utils.SelectorLabelKeySuffix, i): fmt.Sprintf("%s%d", utils.SelectorLabelValueSuffix, i),
		}
		svcs = append(svcs, svc)
	}
	return
}

func scaleUp(ctx context.Context, data *ScaleData, ch chan time.Duration) (svcs []ServiceInfo, err error) {
	provider := data.provider
	controlPlaneNodeName := data.controlPlaneNodes[0]
	cs := data.kubernetesClientSet
	nss := data.namespaces
	numPerNs := data.Specification.SvcNumPerNs
	ipv6 := data.Specification.IPv6
	start := time.Now()

	var svcCIDRs []string
	klog.InfoS("retrieving service CIDRs", "controlPlaneNodeName", controlPlaneNodeName)
	svcCIDRs, err = retrieveCIDRs(provider, controlPlaneNodeName, "kubectl cluster-info dump | grep service-cluster-ip-range", `service-cluster-ip-range=([^"]+)`)
	if err != nil {
		// Retrieve service CIDRs for Rancher clusters.
		svcCIDRs, err = retrieveCIDRs(provider, controlPlaneNodeName, "ps aux | grep kube-controller | grep service-cluster-ip-range", `service-cluster-ip-range=([^\s]+)`)
		if err != nil {
			klog.ErrorS(err, "retrieveCIDRs")
			return
		}
	}

	klog.InfoS("retrieveCIDRs", "svcCIDRs", svcCIDRs)
	svcCIDRIPv4 := svcCIDRs[0]
	_, ipNet, _ := net.ParseCIDR(svcCIDRIPv4)
	allocator, err := ipallocator.NewCIDRAllocator(ipNet, []net.IP{net.ParseIP("10.96.0.1"), net.ParseIP("10.96.0.10")})

	for _, ns := range nss {
		klog.InfoS("Scale up Services", "Namespace", ns)
		var services []*corev1.Service
		services, err = renderServices(data.templateFilesPath, numPerNs)
		if err != nil {
			return
		}
		for _, svc := range services {
			if ipv6 {
				ipFamily := corev1.IPv6Protocol
				svc.Spec.IPFamilies = []corev1.IPFamily{ipFamily}
			}
			if err := utils.DefaultRetry(func() error {
				var clusterIP net.IP
				clusterIP, err = allocator.AllocateNext()
				if err != nil {
					return fmt.Errorf("allocate IP from ServiceCIDR error: %+v", err)
				}

				var newSvc *corev1.Service
				var err error
				var clientPod *corev1.Pod
				svc.Spec.ClusterIP = clusterIP.String()
				klog.InfoS("go FetchTimestampFromLog", "cap(ch)", cap(ch), "len(ch)", len(ch))
				clientPod, err = client_pod.CreatePod(ctx, cs, []string{fmt.Sprintf("%s:%d", clusterIP, 80)}, client_pod.ScaleTestPodProbeContainerName, ns)
				if err != nil || clientPod == nil {
					klog.ErrorS(err, "Create client test Pod failed, can not verify the Service, will exist")
					return err
				}
				startTime0 := time.Now().UnixNano()
				newSvc, err = cs.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{})
				if err != nil {
					if errors.IsAlreadyExists(err) {
						newSvc, _ = cs.CoreV1().Services(ns).Get(ctx, svc.Name, metav1.GetOptions{})
					} else {
						return err
					}
				}

				if newSvc.Spec.ClusterIP == "" {
					return fmt.Errorf("service %s Spec.ClusterIP is empty", svc.Name)
				}
				klog.InfoS("Create Service", "Name", newSvc.Name, "ClusterIP", newSvc.Spec.ClusterIP, "Namespace", ns)
				svcs = append(svcs, ServiceInfo{Name: newSvc.Name, IP: newSvc.Spec.ClusterIP, NameSpace: newSvc.Namespace})
				go func() {
					startTimeStamp := time.Now().UnixNano()
					klog.InfoS("Service creating operate time", "Duration(ms)", (startTimeStamp-startTime0)/1000000)
					key := "down to up"
					if err := utils.FetchTimestampFromLog(ctx, cs, clientPod.Namespace, clientPod.Name, client_pod.ScaleTestPodProbeContainerName, ch, startTimeStamp, key); err != nil {
						klog.ErrorS(err, "Check readiness of service error", "ClientPodName", clientPod.Name, "svc", svc)
					}
					klog.InfoS("Update test Pod to check Service", "ClusterIP", clusterIP)
				}()
				return nil
			}); err != nil {
				return nil, err
			}
			time.Sleep(time.Duration(utils.GenRandInt()%2000) * time.Millisecond)
		}
	}
	klog.InfoS("Scale up Services", "Duration", time.Since(start), "count", len(svcs))
	return
}

func scaleDown(ctx context.Context, data *ScaleData, svcs []ServiceInfo) error {
	cs := data.kubernetesClientSet
	for _, svc := range svcs {
		if err := cs.CoreV1().Services(svc.NameSpace).Delete(ctx, svc.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
		klog.V(2).InfoS("Deleted service", "serviceName", svc)
	}
	return wait.PollImmediateUntil(config.WaitInterval, func() (done bool, err error) {
		count := 0
		for _, svc := range svcs {
			if err := cs.CoreV1().Services(svc.NameSpace).Delete(ctx, svc.Name, metav1.DeleteOptions{}); errors.IsNotFound(err) {
				count++
			}
		}
		klog.InfoS("Scale down Services", "Services", len(svcs), "cleanedUpCount", count)
		return count == len(svcs), nil
	}, ctx.Done())
}
