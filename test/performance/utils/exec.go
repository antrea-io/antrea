// Copyright 2024 Antrea Authors
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
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	defaultInterval = 1 * time.Second
	defaultTimeout  = 3 * time.Minute
	DownToUp        = "down to up"
	UpToDown        = "up to down"
)

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
	err := wait.PollUntilContextTimeout(ctx, defaultInterval, defaultTimeout, false, func(ctx context.Context) (done bool, err error) {
		req := kc.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
			Container: containerName,
		})
		podLogs, err := req.Stream(ctx)
		if err != nil {
			klog.ErrorS(err, "error when opening stream to retrieve logs for Pod", "Namespace", namespace, "PodName", podName)
			return false, nil
		}
		defer podLogs.Close()

		var b bytes.Buffer
		if _, err := io.Copy(&b, podLogs); err != nil {
			return false, fmt.Errorf("error when copying logs for Pod '%s/%s': %w", namespace, podName, err)
		}
		klog.V(4).InfoS("GetLogs from probe container", "PodName", podName, "Namespace", namespace, "logs", b.String())
		if strings.Contains(b.String(), key) {
			changedTimeStamp, err := extractNanoseconds(b.String(), key)
			if err != nil {
				return false, fmt.Errorf("extract timestamp from log error: %+v, PodName: %s, PodName: %s", err, namespace, podName)
			}
			if time.Duration(changedTimeStamp-startTime) < 0 {
				// Probe every 100ms. If the TCP disconnection occurs exactly within this 100ms interval,
				// the timestamp might be earlier than the start time we recorded. To reduce the error, we take 50ms as the result.
				if time.Duration(startTime-changedTimeStamp) < 100*time.Millisecond {
					changedTimeStamp = startTime + int64(50*time.Millisecond)
					klog.InfoS("The TCP disconnection occurs exactly within this 100ms interval, change the timestamp within 100ms", "newChangedTimeStamp", changedTimeStamp, "startTime", startTime)
				} else {
					klog.ErrorS(nil, "timestamp fetch from the client Pod log is invalid, please check", "Namespace", namespace, "PodName", podName, "startTime", startTime, "changedTime", changedTimeStamp)
					return false, nil
				}
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
	if err != nil {
		return err
	}
	if err := kc.CoreV1().Pods(namespace).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("delete the client Pod error: %+v", err)
	}
	return nil
}
