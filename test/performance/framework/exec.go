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
	"fmt"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"antrea.io/antrea/test/performance/utils"
)

func ExecURL(clientPod *corev1.Pod, kClient kubernetes.Interface, peerIP string) *url.URL {
	return kClient.CoreV1().RESTClient().Post().
		Namespace(clientPod.Namespace).
		Resource("pods").
		Name(clientPod.Name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 1 %s 80", peerIP)},
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec).URL()
}

func PingIP(kubeConfig *rest.Config, p kubernetes.Interface, pod *corev1.Pod, ip string) error {
	executor, err := remotecommand.NewSPDYExecutor(kubeConfig, "POST", ExecURL(pod, p, ip))
	if err != nil {
		return fmt.Errorf("error when creating SPDY executor: %w", err)
	}

	// Try to execute command with failure tolerant.
	if err = utils.DefaultRetry(func() error {
		var stdout, stderr bytes.Buffer
		if err := executor.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
			err := fmt.Errorf("executing commands on service client Pod error: %v", err)
			// klog.ErrorS(err, "Check readiness of service", "ServiceName", svc.Name, "ClientPodName", clientPod.Name, "stdout", stdout.String(), "stderr", stderr.String())
			return fmt.Errorf("ping ip %s error: %v, stdout:`%s`, stderr:`%s`, client pod: %s", ip, err, stdout.String(), stderr.String(), pod.Name)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
