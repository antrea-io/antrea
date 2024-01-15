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

package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/client_pod"
)

const (
	defaultInterval = 1 * time.Second
	defaultTimeout  = 3 * time.Minute
)

func ExecURL(kClient kubernetes.Interface, clientPodNamespace, clientPodName, peerIP string) *url.URL {
	return kClient.CoreV1().RESTClient().Post().
		Namespace(clientPodNamespace).
		Resource("pods").Name(clientPodName).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command:   []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 1 %s 80", peerIP)},
			Container: client_pod.ScaleClientContainerName,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec).URL()
}

func WaitUntil(ctx context.Context, ch chan time.Duration, kubeConfig *rest.Config, kc kubernetes.Interface, podNs, podName, ip string, expectErr bool) error {
	var err error
	startTime := time.Now()
	defer func() {
		if err == nil {
			select {
			case ch <- time.Since(startTime):
				klog.InfoS("Successfully write in channel")
			default:
				klog.InfoS("Skipped writing to the channel. No receiver.")
			}
		}
	}()
	err = wait.Poll(defaultInterval, defaultTimeout, func() (bool, error) {
		err := PingIP(ctx, kubeConfig, kc, podNs, podName, ip)
		if (err != nil && !expectErr) || (err == nil && expectErr) {
			return false, fmt.Errorf("error when getting expected condition: %+v", err)
		}
		return true, nil
	})
	return err
}

func PingIP(ctx context.Context, kubeConfig *rest.Config, kc kubernetes.Interface, podNs, podName, ip string) error {
	executor, err := remotecommand.NewSPDYExecutor(kubeConfig, "POST", ExecURL(kc, podNs, podName, ip))
	if err != nil {
		return fmt.Errorf("error when creating SPDY executor: %w", err)
	}

	// Try to execute command with failure tolerant.
	if err = DefaultRetry(func() error {
		var stdout, stderr bytes.Buffer
		if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
			err := fmt.Errorf("executing commands on service client Pod error: %v", err)
			return fmt.Errorf("ping ip %s error: %v, stdout:`%s`, stderr:`%s`, client pod: %s", ip, err, stdout.String(), stderr.String(), podName)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func extractNanoseconds(logEntry, key string) (int64, error) {
	// re := regexp.MustCompile(fmt.Sprintf(`(\d+)\s+Status changed from (unknown|down|up)? %s after`, key))
	re := regexp.MustCompile(fmt.Sprintf(`(\d+)\s+Status changed from %s after`, key))
	matches := re.FindStringSubmatch(logEntry)

	if len(matches) < 2 {
		return 0, fmt.Errorf("no nanoseconds found in the log entry")
	}

	timestampStr := matches[1]
	// 1709088530251243475
	// 170908853117632348
	// not sure why some timestamps fetch from logs are invalid
	for len(timestampStr) < 19 {
		timestampStr += "0"
	}
	nanoseconds, err := strconv.Atoi(timestampStr)
	if err != nil {
		return 0, fmt.Errorf("error converting nanoseconds to integer: %v", err)
	}

	return int64(nanoseconds), nil
}

func FetchTimestampFromLog(ctx context.Context, kc kubernetes.Interface, namespace, podName, containerName string, ch chan time.Duration, startTime int64, key string) error {
	return wait.Poll(defaultInterval, defaultTimeout, func() (done bool, err error) {
		req := kc.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
			Container: containerName,
		})
		podLogs, err := req.Stream(ctx)
		if err != nil {
			klog.ErrorS(err, "error when opening stream to retrieve logs for Pod", "namespace", namespace, "podName", podName)
			return false, nil
		}
		defer podLogs.Close()

		var b bytes.Buffer
		if _, err := io.Copy(&b, podLogs); err != nil {
			return false, fmt.Errorf("error when copying logs for Pod '%s/%s': %w", namespace, podName, err)
		}
		klog.V(4).InfoS("GetLogs from probe container", "podName", podName, "namespace", namespace, "logs", b.String())
		if strings.Contains(b.String(), key) {
			changedTimeStamp, err := extractNanoseconds(b.String(), key)
			if err != nil {
				return false, err
			}
			if time.Duration(changedTimeStamp-startTime) < 0 {
				klog.ErrorS(nil, "timestamp fetch from the client Pod log is invalid, please check", "startTime", startTime, "chengedTime", changedTimeStamp)
				return false, nil
			}
			select {
			case ch <- time.Duration(changedTimeStamp - startTime):
				klog.InfoS("Successfully write in channel", "ChangedTimeStamp", changedTimeStamp, "startTime", startTime)
			default:
				klog.InfoS("Skipped writing to the channel. No receiver.")
			}
			return true, nil
		}
		return false, nil
	})
}
