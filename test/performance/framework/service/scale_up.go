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

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/utils"
)

func generateService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("antrea-scale-test-svc-%s", uuid.New().String()),
		},
		Spec: corev1.ServiceSpec{
			Selector: utils.PickLabels(6, true), // each service select 25% pods on real nodes.
			Ports: []corev1.ServicePort{
				{
					Protocol: corev1.ProtocolTCP,
					Port:     80,
				},
			},
		},
	}
}

type ServiceInfo struct {
	Name      string
	IP        string
	NameSpace string
}

func ScaleUp(ctx context.Context, num int, cs kubernetes.Interface, nss []string, ipv6 bool) (svcs []ServiceInfo, err error) {
	start := time.Now()
	for _, ns := range nss {
		klog.InfoS("Scale up Services", "Num", num, "Namespace", ns)
		for i := 0; i < num; i++ {
			svc := generateService()
			if ipv6 {
				ipFamily := corev1.IPv6Protocol
				svc.Spec.IPFamilies = []corev1.IPFamily{ipFamily}
			}
			if err := utils.DefaultRetry(func() error {
				var newSvc *corev1.Service
				var err error
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
				return nil
			}); err != nil {
				return nil, err
			}
			time.Sleep(time.Duration(utils.GenRandInt()%2000) * time.Millisecond)
		}
	}
	klog.InfoS("Scale Service time", "Duration", time.Since(start))
	return
}
