// Copyright 2024 Antrea Authors.
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

package check

import (
	"bytes"
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type Client struct {
	clientSet   kubernetes.Interface
	config      *rest.Config
	clusterName string
}

func NewClient() (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()

	nonInteractiveClient := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})

	config, err := nonInteractiveClient.ClientConfig()
	if err != nil {
		return nil, err
	}

	rawConfig, err := nonInteractiveClient.RawConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	contextName := rawConfig.CurrentContext

	clusterName := ""
	if context, ok := rawConfig.Contexts[contextName]; ok {
		clusterName = context.Cluster
	}

	return &Client{
		clientSet:   clientset,
		config:      config,
		clusterName: clusterName,
	}, nil
}

func (c *Client) GetClientSet() kubernetes.Interface {
	return c.clientSet
}

func (c *Client) ClusterName() (name string) {
	return c.clusterName
}

func (c *Client) DeploymentIsReady(ctx context.Context, namespace, deploymentName string) (bool, error) {
	deployment, err := c.clientSet.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if deployment.Generation <= deployment.Status.ObservedGeneration {
		for _, cond := range deployment.Status.Conditions {
			if cond.Type == appsv1.DeploymentProgressing && cond.Reason == "ProgressDeadlineExceeded" {
				return false, fmt.Errorf("deployment %q exceeded its progress deadline", deployment.Name)
			}
		}
		if deployment.Spec.Replicas != nil && deployment.Status.UpdatedReplicas < *deployment.Spec.Replicas {
			return false, nil
		}
		if deployment.Status.Replicas > deployment.Status.UpdatedReplicas {
			return false, nil
		}
		if deployment.Status.AvailableReplicas < deployment.Status.UpdatedReplicas {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

func (c *Client) ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error) {
	req := c.clientSet.CoreV1().RESTClient().Post().Resource("pods").Name(pod).Namespace(namespace).SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Command:   command,
		Container: container,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error while creating executor: %w", err)
	}
	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error in stream: %w", err)
	}
	fmt.Fprint(&stdout, stderr.String())
	return stdout, nil
}
